package main

import (
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

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

// GetSchoolInfo 从重定向响应头中获取学校信息和索引URL
func (c *Client) GetSchoolInfo() error {
	if c.RedirectUrl == "" {
		return errors.New("missing redirect URL")
	}

	request, err := c.NewGetRequest(c.RedirectUrl)
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
	defer func(Body io.ReadCloser) {
		if Body != nil {
			_ = Body.Close()
		}
	}(response.Body)

	if response.Header.Get("domain") != "" && response.Header.Get("area") != "" &&
		response.Header.Get("schoolid") != "" && response.Header.Get("Location") != "" {
		c.Domain = response.Header.Get("domain")
		c.Area = response.Header.Get("area")
		c.SchoolID = response.Header.Get("schoolid")
		c.IndexUrl = response.Header.Get("Location")
	} else {
		return errors.New("missing school info")
	}

	if response.StatusCode != 302 {
		return errors.New("invalid process of authorization at stage 2")
	}

	return nil
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

	// keepRetry 解析失败时使用默认 60 秒，避免登录已成功却整体判定失败
	keepRetrySec, err := strconv.Atoi(loginResponseXML.KeepRetry)
	if err != nil || keepRetrySec <= 0 {
		keepRetrySec = 60
	}

	c.heartBeatTicker.Reset(time.Second * time.Duration(keepRetrySec))
	return nil
}
