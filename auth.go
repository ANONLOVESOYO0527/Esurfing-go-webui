package main

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxAuthRedirects 认证入口重定向链最大跳数（参考官方客户端：逐跳采集路由头直至门户页）
const maxAuthRedirects = 6

// UA 回退类错误（docs/08 §3.3）：服务端按 UA 分流，换 UA 重试有意义。
// 网络层错误（重定向链失败、超时）不属于此类——换 UA 无意义，直接失败。
var (
	errPortalPageUnusable = errors.New("portal page unusable for this user-agent")
	errZSMRejected        = errors.New("zsm handshake rejected")
	errZSMEmptyBody       = errors.New("zsm empty response")
	errZSMUnparseable     = errors.New("zsm response unparseable")
	errUnknownAlgoID      = errors.New("unknown algo id")
)

func isUAFallbackError(err error) bool {
	return errors.Is(err, errPortalPageUnusable) ||
		errors.Is(err, errZSMRejected) ||
		errors.Is(err, errZSMEmptyBody) ||
		errors.Is(err, errZSMUnparseable) ||
		errors.Is(err, errUnknownAlgoID)
}

// Auth 执行完整认证流程：解析 UA 回退链 → 逐 UA 尝试（学校信息→配置→算法ID→票据→登录）。
// URL 为空时（黑洞强制重认证）复用上次认证的重定向 URL：门户地址通常为 IP 直连，
// 不依赖 DNS，可在 DNS 黑洞场景下独立完成重认证。
// 回退触发条件（实测语义见 docs/05 §3.3、§12）：门户页不可用 / ZSM 被拒 /
// ZSM 空体或不可解析 / 未知 GUID（第四代兑底）；链耗尽时列出全部尝试记录。
func (c *Client) Auth(URL string) error {
	if URL != "" {
		c.RedirectUrl = URL
	}

	c.resolveUAChain()

	var attempts []string
	for c.uaIdx = 0; c.uaIdx < len(c.uaChain); c.uaIdx++ {
		ua := c.uaChain[c.uaIdx]
		c.resetSession()

		if err := c.GetSchoolInfo(); err != nil {
			return err // 网络层错误：换 UA 无意义
		}
		if err := c.GetEConfig(); err != nil {
			if errors.Is(err, errPortalPageUnusable) {
				attempts = append(attempts, fmt.Sprintf("ua=%s: %v", ua, err))
				c.logf("warn", "portal page unusable with ua=%s: %v, trying next ua", ua, err)
				continue
			}
			return err
		}
		if err := c.GetUserAndAcIP(); err != nil {
			return err
		}
		if err := c.GetAlgoId(); err != nil {
			if isUAFallbackError(err) {
				attempts = append(attempts, fmt.Sprintf("ua=%s: %v", ua, err))
				c.logf("warn", "zsm handshake failed with ua=%s: %v, trying next ua", ua, err)
				continue
			}
			return err
		}

		c.cipher = NewCipher(c.AlgoID)
		if c.cipher == nil {
			// AlgoID 为服务端可控字节，过 sanitize 防日志伪造
			err := fmt.Errorf("%w: %s（不在已知 24 个算法 ID 内，可能是新代际，可反馈该 GUID）",
				errUnknownAlgoID, sanitizeSnippet([]byte(c.AlgoID), 36))
			attempts = append(attempts, fmt.Sprintf("ua=%s: %v", ua, err))
			c.logf("warn", "%v", err)
			continue
		}

		c.logln("info", "user-agent: "+ua)
		c.logln("info", "algo_id: "+sanitizeSnippet([]byte(c.AlgoID), 36))

		// 链内成功：记忆本 UA（SessionData 持久化由 manager 回调完成），
		// 后续 ticket/login/心跳/term 全程沿用
		c.preferredUA = ua

		if err := c.GetTicket(); err != nil {
			return err
		}

		c.logln("info", "ticket: "+sanitizeSnippet([]byte(c.Ticket), 64))

		time.Sleep(time.Millisecond * 333)

		if err := c.Login(); err != nil {
			return err
		}

		c.authed.Store(true)
		return nil
	}

	return fmt.Errorf("auth failed: all user agents rejected:\n  %s", strings.Join(attempts, "\n  "))
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
		// 门户页形态随 UA 家族不同（phone 27KB / PC 22KB，docs/05 §12）：
		// 对某 UA 无配置块时换下一个 UA 重试（如 Win/Mac 族的异形页面）
		return fmt.Errorf("%w: %v", errPortalPageUnusable, err)
	}

	eConfig := &EConfig{}

	err = xml.Unmarshal(eConfigData, eConfig)
	if err != nil {
		return fmt.Errorf("%w: %v", errPortalPageUnusable, err)
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

	// ZSM 判定顺序（与 L3 参照实现 debug 工具一致）：**先解析 body，解析成功即成功**，
	// Error-Code 仅在响应不可用时作为诊断信息——避免未观测的“合法 payload + EC≠200”
	// 形态被误杀（如某门户 ZSM 成功沿用业务码 0）；实测拒绝形态（HTTP 200 +
	// EC=3 + 空体，docs/05 §2）落入空体分支。
	// ⚠️ Error-Code 头**缺失**视为成功：mock 环境与部分老门户不下发该头（docs/08 §3.3 兼容规则）。
	if len(algoIdData) == 0 {
		if ec := response.Header.Get("Error-Code"); ec != "" && ec != "200" {
			return fmt.Errorf("%w: ua=%s error_code=%s sub_error=%q server=%q",
				errZSMRejected, c.currentUA(), ec, response.Header.Get("Sub-Error"), response.Header.Get("Server-Tag"))
		}
		return fmt.Errorf("%w: ua=%s error_code=%q sub_error=%q server=%q (0 bytes)",
			errZSMEmptyBody, c.currentUA(),
			response.Header.Get("Error-Code"), response.Header.Get("Sub-Error"), response.Header.Get("Server-Tag"))
	}

	c.AlgoID, _, err = DecodeAlgoID(algoIdData)
	if err != nil {
		return fmt.Errorf("%w: ua=%s error_code=%q sub_error=%q server=%q: %v (zsm head: %s)",
			errZSMUnparseable, c.currentUA(),
			response.Header.Get("Error-Code"), response.Header.Get("Sub-Error"), response.Header.Get("Server-Tag"),
			err, sanitizeSnippet(algoIdData, 64))
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
