package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// maxAuthRedirects 认证入口重定向链最大跳数（参考官方客户端：逐跳采集路由头直至门户页）
const maxAuthRedirects = 6

// Auth 执行完整认证流程：获取学校信息 -> 获取配置 -> 获取算法ID -> 获取票据 -> 登录
// URL 为空时（黑洞强制重认证）复用上次认证的重定向 URL：门户地址通常为 IP 直连，
// 不依赖 DNS，可在 DNS 黑洞场景下独立完成重认证
func (c *Client) Auth(URL string) error {
	log := c.Log
	if URL != "" {
		c.RedirectUrl = URL
	}

	err := c.GetSchoolInfo()
	if err != nil {
		return err
	}

	c.ClientID = uuid.New()
	c.Hostname = GenerateRandomString(10)
	c.MacAddress = GenerateRandomMAC()

	err = c.GetEConfig()
	if err != nil {
		return err
	}

	err = c.GetUserAndAcIP()
	if err != nil {
		return err
	}

	err = c.GetAlgoId()
	if err != nil {
		return err
	}

	c.cipher = NewCipher(c.AlgoID)
	if c.cipher == nil {
		return errors.New("Unknown AlgoID:" + c.AlgoID)
	}

	log.Println("algo_id:", c.AlgoID)

	err = c.GetTicket()
	if err != nil {
		return err
	}

	log.Println("ticket:", c.Ticket)

	time.Sleep(time.Millisecond * 333)

	err = c.Login()
	if err != nil {
		return err
	}

	c.authed.Store(true)
	return nil
}

// GetUserAndAcIP 从票据URL中解析用户IP和AC IP
func (c *Client) GetUserAndAcIP() error {
	URLParsed, err := url.Parse(c.TicketUrl)
	if err != nil {
		return err
	}

	c.UserIP = URLParsed.Query().Get("wlanuserip")
	c.AcIP = URLParsed.Query().Get("wlanacip")

	if c.UserIP == "" || c.AcIP == "" {
		return errors.New("missing user ip or ac ip")
	}

	return nil
}

// GetEConfig 从认证页面获取服务器配置（票据URL、认证URL等）
func (c *Client) GetEConfig() error {
	if c.IndexUrl == "" {
		return errors.New("missing index url")
	}

	request, err := c.NewGetRequest(c.IndexUrl)
	if err != nil {
		return err
	}

	response, err := c.HttpClient.Do(request)
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("nil response from GetEConfig request")
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	data, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody))
	if err != nil {
		return err
	}

	// 非 2xx 时响应体不可能是门户配置页，直接失败并携带状态码
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("portal config page http %d from %s", response.StatusCode, c.IndexUrl)
	}

	eConfigData, err := FormatEConfig(data)
	if err != nil {
		return err
	}

	eConfig := &EConfig{}

	err = xml.Unmarshal(eConfigData, eConfig)
	if err != nil {
		return err
	}

	c.TicketUrl = eConfig.TicketURL
	c.AuthUrl = eConfig.AuthURL

	return nil
}

// GetSchoolInfo 沿重定向链逐跳采集学校路由信息（schoolid/domain/area），
// 并定位门户配置页（重定向链终点）。
// 路由头可能分散在不同跳的响应中，逐跳累积；它们是“若已知则回传”的字段，
// 缺失不视为失败。支持相对 Location 与 301/302/303/307/308。
func (c *Client) GetSchoolInfo() error {
	if c.RedirectUrl == "" {
		return errors.New("missing redirect URL")
	}

	current := c.RedirectUrl
	for hop := 0; hop < maxAuthRedirects; hop++ {
		request, err := c.NewGetRequest(current)
		if err != nil {
			return err
		}

		response, err := c.HttpClient.Do(request)
		if err != nil {
			return err
		}
		if response == nil {
			return errors.New("nil response from GetSchoolInfo request")
		}

		c.harvestCDC(response)

		location := response.Header.Get("Location")
		if isRedirectStatus(response.StatusCode) {
			_ = response.Body.Close()
			if location == "" {
				return fmt.Errorf("redirect without Location at hop %d", hop)
			}
			next, perr := request.URL.Parse(location)
			if perr != nil {
				return fmt.Errorf("invalid redirect location %q: %w", location, perr)
			}
			current = next.String()
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody))
		_ = response.Body.Close()
		if readErr != nil {
			return readErr
		}

		// 页面内 JS 跳转（location.href 等）：部分门户不用 HTTP 重定向而是返回
		// 带脚本的 HTML，继续跟随直到跳数预算耗尽或到达静态配置页
		if js := extractJSRedirect(string(body)); js != "" {
			if next, perr := request.URL.Parse(js); perr == nil {
				current = next.String()
				continue
			}
			// 解析失败则按普通着陆页处理，交给 GetEConfig 报出明确错误
		}

		// 链终点（非重定向响应）：该 URL 即门户配置页，交给 GetEConfig 解析
		c.IndexUrl = current
		return nil
	}
	return errors.New("too many redirects while resolving portal page")
}

// GetAlgoId 获取加密算法ID
func (c *Client) GetAlgoId() error {
	request, err := c.NewPostRequest(c.TicketUrl, []byte(c.AlgoID))
	if err != nil {
		return err
	}

	response, err := c.HttpClient.Do(request)
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("nil response from GetAlgoId request")
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	algoIdData, err := io.ReadAll(io.LimitReader(response.Body, maxHTTPBody))
	if err != nil {
		return err
	}

	// 非 2xx（网关错误页等）不可能是合法 ZSM 二进制，直接失败并携带片段便于诊断
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("zsm handshake http %d: %s", response.StatusCode, sanitizeSnippet(algoIdData, 60))
	}

	c.AlgoID, _, err = DecodeAlgoID(algoIdData)
	if err != nil {
		return err
	}

	return nil
}

// GetTicket 请求并获取认证票据
func (c *Client) GetTicket() error {
	getTicketXML, err := c.GenerateGetTicketXML()
	if err != nil {
		return err
	}

	ticketData, err := c.PostXML(c.TicketUrl, getTicketXML)
	if err != nil {
		return err
	}

	ticketXML := &TicketResponse{}

	err = xml.Unmarshal(ticketData, ticketXML)
	if err != nil {
		return err
	}

	c.Ticket = ticketXML.Ticket
	return nil
}

// Login 发送登录请求，获取心跳URL和间隔
func (c *Client) Login() error {
	loginXML, err := c.GenerateLoginXML()
	if err != nil {
		return err
	}

	responseData, err := c.PostXML(c.AuthUrl, loginXML)
	if err != nil {
		return err
	}

	loginResponseXML := &LoginResponse{}
	err = xml.Unmarshal(responseData, loginResponseXML)
	if err != nil {
		return err
	}

	c.KeepUrl = loginResponseXML.KeepURL
	c.TermUrl = loginResponseXML.TermURL

	// 登录被服务端拒绝时（密码错误、欠费等），响应报文不含 keep-url。
	// 此时必须判定为失败并进入重试流程，而不是带空 URL 进入心跳循环；
	// 同时把解密后的响应片段放进错误信息，便于直接看到拒绝原因。
	if c.KeepUrl == "" {
		return fmt.Errorf("login rejected, no keep-url in response: %s", sanitizeSnippet(responseData, 160))
	}

	// keepRetry 解析失败时使用默认 60 秒，避免登录已成功却整体判定失败
	keepRetrySec, err := strconv.Atoi(loginResponseXML.KeepRetry)
	if err != nil || keepRetrySec <= 0 {
		keepRetrySec = 60
	}

	c.heartBeatTicker.Reset(time.Second * time.Duration(keepRetrySec))
	return nil
}
