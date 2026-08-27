package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"net/http"
)

// cctpAccept 所有 CCTP 请求共用的 Accept 头
const cctpAccept = "text/html,text/xml,application/xhtml+xml,application/x-javascript,*/*"

// setCDCRoutingHeaders 设置路由头（schoolid/domain/area）。
// 协议约定为“若已知则回传”：认证链中每一跳采集到的路由头要跟随后续所有请求，
// 帮助服务端定位学校/区域上下文（GET 与 POST 业务报文都需要）。
func (c *Client) setCDCRoutingHeaders(req *http.Request) {
	if c.SchoolID != "" {
		req.Header.Set("CDC-SchoolId", c.SchoolID)
	}
	if c.Domain != "" {
		req.Header.Set("CDC-Domain", c.Domain)
	}
	if c.Area != "" {
		req.Header.Set("CDC-Area", c.Area)
	}
}

// NewGetRequest 创建带认证头的 GET 请求
func (c *Client) NewGetRequest(url string) (request *http.Request, err error) {
	req, err := http.NewRequestWithContext(c.Ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgentAndroid)
	req.Header.Set("Accept", cctpAccept)
	req.Header.Set("Client-ID", c.ClientID.String())
	req.Header.Set("Connection", "keep-alive")
	c.setCDCRoutingHeaders(req)

	return req, nil
}

// NewPostRequest 创建带认证头的 POST 请求。
// 协议要求业务 POST 携带 Content-Type: application/x-www-form-urlencoded
// （body 实际并非表单，但服务端按此类型校验）、MD5 校验和与算法 ID；
// 已知路由头同样需要回传。
func (c *Client) NewPostRequest(url string, data []byte) (request *http.Request, err error) {
	md5Hex := md5.Sum(data)

	req, err := http.NewRequestWithContext(c.Ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgentAndroid)
	req.Header.Set("Accept", cctpAccept)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Client-ID", c.ClientID.String())
	req.Header.Set("CDC-Checksum", hex.EncodeToString(md5Hex[:]))
	req.Header.Set("Algo-ID", c.AlgoID)
	c.setCDCRoutingHeaders(req)
	return req, nil
}

// NewPostRequestWithCustomCtx 创建带自定义上下文的 POST 请求（用于超时控制）
func (c *Client) NewPostRequestWithCustomCtx(ctx context.Context, url string, data []byte) (request *http.Request, err error) {
	md5Hex := md5.Sum(data)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgentAndroid)
	req.Header.Set("Accept", cctpAccept)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Client-ID", c.ClientID.String())
	req.Header.Set("CDC-Checksum", hex.EncodeToString(md5Hex[:]))
	req.Header.Set("Algo-ID", c.AlgoID)
	c.setCDCRoutingHeaders(req)
	return req, nil
}

// respCDCHeader 从响应读取路由头，兼容 CDC-* 与裸变体（如 schoolid/CDC-SchoolId）。
// Go 的 Header.Get 会规范化大小写，两种发送形态均可命中。
func respCDCHeader(resp *http.Response, name string) string {
	if v := resp.Header.Get("Cdc-" + name); v != "" {
		return v
	}
	return resp.Header.Get(name)
}

// harvestCDC 从响应头采集路由信息（schoolid/domain/area），已有值会被新出现的值覆盖：
// 越靠近门户页的跳，其路由头越权威。在重定向链的每一跳调用。
func (c *Client) harvestCDC(resp *http.Response) {
	if v := respCDCHeader(resp, "SchoolId"); v != "" {
		c.SchoolID = clampCDCValue(v)
	}
	if v := respCDCHeader(resp, "Domain"); v != "" {
		c.Domain = clampCDCValue(v)
	}
	if v := respCDCHeader(resp, "Area"); v != "" {
		c.Area = clampCDCValue(v)
	}
}

// isRedirectStatus 判断是否 HTTP 重定向状态码
func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}
