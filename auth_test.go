package main

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// newAuthFixture 构造一个完整的认证链路模拟环境（按路径路由，状态无关）：
//
//	GET  /portal   → 302 携带 schoolid/domain/area 路由头与 Location(/econfig)
//	GET  /hop-a    → 302 仅携带 schoolid（多跳链第一跳）
//	GET  /hop-b    → 302 仅携带 domain/area（多跳链第二跳）
//	GET  /econfig  → 200 内嵌门户配置块（起始标记后接换行，验证宽松匹配）
//	POST /ticket   → body 为明文算法 ID 时返回二进制 ZSM；否则视为加密 GetTicket 报文
//	POST /auth     → 加密登录响应（rejectLogin=true 时返回无 keep-url 的拒绝报文）
func newAuthFixture(t *testing.T) (*Client, *authFixture) {
	t.Helper()
	f := &authFixture{algoID: AlgoXTea}

	loginSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(loginSrv.Close)

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		}
		f.record(r, body)

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/portal":
			w.Header().Set("domain", "gd")
			w.Header().Set("area", "area1")
			w.Header().Set("schoolid", "1234")
			w.Header().Set("Location", f.econfigURL())
			w.WriteHeader(http.StatusFound)
		case r.Method == http.MethodGet && r.URL.Path == "/hop-a":
			w.Header().Set("schoolid", "5678")
			w.Header().Set("Location", f.base+"/hop-b")
			w.WriteHeader(http.StatusFound)
		case r.Method == http.MethodGet && r.URL.Path == "/hop-b":
			w.Header().Set("domain", "gd2")
			w.Header().Set("area", "area2")
			w.Header().Set("Location", f.econfigURL())
			w.WriteHeader(http.StatusFound)
		case r.Method == http.MethodGet && r.URL.Path == "/jsredir":
			// 无 HTTP 重定向，纯 JS 跳转型门户
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><script>window.location="` + f.econfigURL() + `"</script></html>`))
		case r.Method == http.MethodGet && r.URL.Path == "/hoprel/start":
			// 相对 Location：无前导斜杠，应解析为 /hoprel/econfig
			w.Header().Set("Location", "econfig")
			w.WriteHeader(http.StatusFound)
		case r.Method == http.MethodGet && (r.URL.Path == "/econfig" || r.URL.Path == "/hoprel/econfig"):
			f.writeConfigPage(w)
		case r.URL.Path == "/ticket":
			// ZSM 握手：body 为 36 字符明文算法 ID
			if len(body) == 36 {
				if _, perr := uuid.Parse(string(body)); perr == nil {
					ua := r.Header.Get("User-Agent")
					// 准入闸形态（docs/05 §2）：HTTP 200 + Error-Code ≠ 200 + 空体
					if ec, bad := f.rejectUAs[ua]; bad {
						w.Header().Set("Error-Code", ec)
						w.Header().Set("Server-Tag", "cdcportal/1.4.2/gd-portal-40")
						w.WriteHeader(http.StatusOK)
						return
					}
					guid := f.algoID
					if f.algoForUA != nil {
						if g := f.algoForUA(ua); g != "" {
							guid = g
						}
					}
					// 真实服务器成功形态带 Error-Code: 200（ZSM 成功码，docs/05 §3.1）
					if !f.omitZSMErrorCode {
						w.Header().Set("Error-Code", "200")
					}
					_, _ = w.Write(buildAlgoIDPayload(guid))
					return
				}
			}
			// 加密 GetTicket 报文：解密留档供断言（XML <user-agent> 契约）
			if pt, derr := f.cipher().Decrypt(body); derr == nil {
				f.mu.Lock()
				f.lastTicketPlain = string(pt)
				f.mu.Unlock()
			}
			enc, _ := f.cipher().Encrypt([]byte(`<?xml version="1.0"?><response><ticket>tkt-123</ticket></response>`))
			_, _ = w.Write(enc)
		case r.URL.Path == "/auth":
			if f.rejectLogin {
				enc, _ := f.cipher().Encrypt([]byte(`<response><rescode>11060001</rescode><message>invalid password</message></response>`))
				_, _ = w.Write(enc)
				return
			}
			enc, _ := f.cipher().Encrypt([]byte(`<?xml version="1.0"?><response><userid>u</userid>` +
				`<keep-retry>60</keep-retry><keep-url>` + loginSrv.URL + `/keep.cgi</keep-url>` +
				`<term-url>` + loginSrv.URL + `/term.cgi</term-url></response>`))
			_, _ = w.Write(enc)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(redirectSrv.Close)

	f.base = redirectSrv.URL

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := &Client{
		Config: &Config{
			Username:      "test",
			Password:      "test",
			CheckInterval: 10000,
			RetryInterval: 10000,
			BindInterface: "sys_default",
		},
		Ctx:    ctx,
		Cancel: cancel,
		// 与生产 NewClient 一致：禁用自动重定向，由认证链手动逐跳处理
		HttpClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ClientID:        mustUUID(),
		AlgoID:          "00000000-0000-0000-0000-000000000000", // 生产路径由 NewClient 设置
		Log:             nopLogger(),
		heartBeatTicker: time.NewTicker(time.Duration(1) << 62),
	}
	return c, f
}

type capturedRequest struct {
	method      string
	path        string
	contentType string
	ua          string
	schoolID    string
	domain      string
	area        string
	algoID      string
	clientID    string
	body        []byte
}

type authFixture struct {
	base        string
	rejectLogin bool

	algoID string // ZSM 握手下发的算法 ID（默认 XTEA；24 ID 循环用）

	// rejectUAs 命中表的 UA 在 ZSM 握手被拒（Error-Code 头 + 空体，模拟真实准入闸形态，docs/05 §2）
	rejectUAs map[string]string // UA → Error-Code

	// algoForUA 可选：按握手 UA 决定下发的 GUID（模拟未知 GUID / 分族算法池）
	algoForUA func(ua string) string

	// omitZSMErrorCode 为 true 时 ZSM 成功响应不带 Error-Code 头（老门户/mock 兼容形态）
	omitZSMErrorCode bool

	mu              sync.Mutex
	captured        []capturedRequest
	lastTicketPlain string // 最近一次加密 GetTicket 请求的解密明文
}

func (f *authFixture) record(r *http.Request, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captured = append(f.captured, capturedRequest{
		method:      r.Method,
		path:        r.URL.Path,
		contentType: r.Header.Get("Content-Type"),
		ua:          r.Header.Get("User-Agent"),
		schoolID:    r.Header.Get("CDC-SchoolId"),
		domain:      r.Header.Get("CDC-Domain"),
		area:        r.Header.Get("CDC-Area"),
		algoID:      r.Header.Get("Algo-ID"),
		clientID:    r.Header.Get("Client-ID"),
		body:        body,
	})
}

func (f *authFixture) requestsByPath(path string) []capturedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []capturedRequest
	for _, cr := range f.captured {
		if cr.path == path {
			out = append(out, cr)
		}
	}
	return out
}

// nextURL 认证入口地址（GetSchoolInfo 重定向链起点）
func (f *authFixture) nextURL() string { return f.base + "/portal" }

// hopURL 多跳重定向链入口（仅首跳携带 schoolid，其余头在后续跳）
func (f *authFixture) hopURL() string { return f.base + "/hop-a" }

// econfigURL 门户配置页地址
func (f *authFixture) econfigURL() string { return f.base + "/econfig" }

// writeConfigPage 输出门户配置页（起始标记后为换行，与真实门户一致）
func (f *authFixture) writeConfigPage(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!DOCTYPE html><!--//config.campus.js.chinatelecom.com\n" +
		`<config><ticket-url>` + xmlEsc(f.ticketURL()) + `</ticket-url><auth-url>` + xmlEsc(f.authURL()) + `</auth-url></config>` +
		"\n//config.campus.js.chinatelecom.com-->"))
}

func (f *authFixture) ticketURL() string {
	return f.base + "/ticket?wlanuserip=10.0.0.1&wlanacip=10.0.0.2"
}

func (f *authFixture) authURL() string { return f.base + "/auth" }

// cipher 使用当次 ZSM 握手协商的算法 ID（默认 XTEA 纯软件实现，无平台差异）
func (f *authFixture) cipher() Cipher { return NewCipher(f.algoID) }

func mustUUID() uuid.UUID { return uuid.New() }

// xmlEsc 将 URL 中的 XML 特殊字符转义
func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// buildAlgoIDPayload 构造 ZSM 握手响应的二进制结构：
// [4字节头 byte[3]=keyLen] [key] ['$'] [36字节算法ID]（分隔符值 0x24 恰为 36）
func buildAlgoIDPayload(algoID string) []byte {
	key := []byte("testkey")
	out := []byte{0, 0, 0, byte(len(key))}
	out = append(out, key...)
	out = append(out, '$')
	out = append(out, algoID...)
	return out
}

// zsmHandshakes 返回已捕获的 ZSM 握手请求（body 为 36 字符合法 UUID）及其 UA
func (f *authFixture) zsmHandshakes() []capturedRequest {
	var out []capturedRequest
	for _, cr := range f.requestsByPath("/ticket") {
		if len(cr.body) == 36 {
			if _, err := uuid.Parse(string(cr.body)); err == nil {
				out = append(out, cr)
			}
		}
	}
	return out
}

// uaCount 统计指定 UA 的 ZSM 握手次数
func (f *authFixture) uaCount(ua string) int {
	n := 0
	for _, cr := range f.zsmHandshakes() {
		if cr.ua == ua {
			n++
		}
	}
	return n
}

// --- 完整认证链路集成测试 ---

func TestAuthFullFlow(t *testing.T) {
	c, f := newAuthFixture(t)

	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("auth flow failed: %v", err)
	}

	if c.Ticket != "tkt-123" {
		t.Fatalf("expected ticket tkt-123, got %q", c.Ticket)
	}
	if !strings.Contains(c.KeepUrl, "/keep.cgi") {
		t.Fatalf("unexpected KeepUrl %q", c.KeepUrl)
	}
	if !strings.Contains(c.TermUrl, "/term.cgi") {
		t.Fatalf("unexpected TermUrl %q", c.TermUrl)
	}
	if c.IndexUrl != f.econfigURL() {
		t.Fatalf("IndexUrl should point at portal config page, got %q", c.IndexUrl)
	}
	if !c.authed.Load() {
		t.Fatal("authed should be true after successful auth")
	}
}

// --- 协议契约：业务 POST 必须携带 Content-Type 与 CDC-* 路由头 ---

func TestAuthPostHeadersContract(t *testing.T) {
	c, f := newAuthFixture(t)

	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("auth flow failed: %v", err)
	}

	posts := 0
	for _, p := range f.requestsByPath("/ticket") {
		posts++
		if p.contentType != "application/x-www-form-urlencoded" {
			t.Fatalf("/ticket POST missing Content-Type, got %q", p.contentType)
		}
		if p.clientID != c.ClientID.String() {
			t.Fatalf("Client-ID mismatch: %q", p.clientID)
		}
		// 路由头在认证链中采集后必须回传到所有业务 POST
		if p.schoolID != "1234" || p.domain != "gd" || p.area != "area1" {
			t.Fatalf("CDC routing headers not propagated: school=%q domain=%q area=%q", p.schoolID, p.domain, p.area)
		}
	}
	for _, p := range f.requestsByPath("/auth") {
		posts++
		if p.contentType != "application/x-www-form-urlencoded" {
			t.Fatalf("/auth POST missing Content-Type, got %q", p.contentType)
		}
	}
	if posts != 3 { // ZSM 握手 + GetTicket + Login
		t.Fatalf("expected 3 business POSTs (handshake/ticket/login), got %d", posts)
	}

	ticketReqs := f.requestsByPath("/ticket")
	if ticketReqs[0].algoID != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("handshake should carry initial zero algo-id, got %q", ticketReqs[0].algoID)
	}
	if ticketReqs[1].algoID != AlgoXTea {
		t.Fatalf("post-handshake requests should carry negotiated algo id, got %q", ticketReqs[1].algoID)
	}
}

// --- 多跳重定向：CDC 路由头跨跳累积采集 ---

func TestAuthMultiHopRedirectAccumulatesRoutingHeaders(t *testing.T) {
	c, f := newAuthFixture(t)

	// /hop-a 只带 schoolid → /hop-b 带 domain/area → /econfig 落地
	if err := c.Auth(f.hopURL()); err != nil {
		t.Fatalf("multi-hop auth failed: %v", err)
	}

	if c.SchoolID != "5678" {
		t.Fatalf("schoolid from first hop lost, got %q", c.SchoolID)
	}
	if c.Domain != "gd2" || c.Area != "area2" {
		t.Fatalf("domain/area from later hop not collected, got %q/%q", c.Domain, c.Area)
	}
	if c.IndexUrl != f.econfigURL() {
		t.Fatalf("landing page URL expected, got %q", c.IndexUrl)
	}
	if !c.authed.Load() {
		t.Fatal("auth should succeed across multi-hop redirect chain")
	}
}

// --- 登录被拒：响应无 keep-url 必须判定失败且不置位 authed ---

func TestAuthLoginRejectionFails(t *testing.T) {
	c, f := newAuthFixture(t)
	f.rejectLogin = true

	err := c.Auth(f.nextURL())
	if err == nil {
		t.Fatal("login rejection should surface an error")
	}
	if !strings.Contains(err.Error(), "login rejected") {
		t.Fatalf("error should mention login rejected, got: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid password") {
		t.Fatalf("error should carry decrypted response snippet, got: %v", err)
	}
	if c.authed.Load() {
		t.Fatal("authed must stay false when login is rejected")
	}
}

// --- 黑洞自愈集成：强制重认证复用缓存的 RedirectUrl ---

func TestBlackholeForceReauthReusesCachedRedirect(t *testing.T) {
	c, f := newAuthFixture(t)

	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("initial auth failed: %v", err)
	}
	c.authed.Store(false)

	// 黑洞强制重认证：resp=nil, RedirectUrl 应复用而非丢失
	if err := c.HandleRedirect(nil); err != nil {
		t.Fatalf("force re-auth failed: %v", err)
	}
	if !c.authed.Load() {
		t.Fatal("force re-auth should succeed via cached RedirectUrl")
	}
	if c.Ticket != "tkt-123" {
		t.Fatalf("expected fresh ticket, got %q", c.Ticket)
	}
}

// --- local-time 必须是固定东八区的当前时刻（与设备本地时区无关） ---

func TestXMLLocalTimeIsUTCPlus8(t *testing.T) {
	got := xmlLocalTime()
	parsed, err := time.ParseInLocation(time.DateTime, got, cstZone)
	if err != nil {
		t.Fatalf("local-time not parseable: %v", err)
	}
	delta := parsed.Sub(time.Now())
	if delta < -5*time.Second || delta > 5*time.Second {
		t.Fatalf("local-time should be the current UTC+8 instant, got %q (delta %v)", got, delta)
	}
}

// --- 心跳成功但 interval 缺失时不得判为心跳失败 ---

func TestSendHeartbeatKeepsIntervalWhenServerOmitsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 真实服务端偶发不回传 interval：心跳应视为成功并保持现有间隔
		enc, _ := NewCipher(AlgoXTea).Encrypt([]byte(`<response><interval></interval><level>1</level></response>`))
		_, _ = w.Write(enc)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{
		Config:                &Config{Username: "u", Password: "p"},
		Ctx:                   ctx,
		HttpClient:            &http.Client{},
		ClientID:              mustUUID(),
		Ticket:                "tkt",
		KeepUrl:               srv.URL,
		cipher:                NewCipher(AlgoXTea),
		Log:                   nopLogger(),
		lastHeartbeatInterval: 90,
		heartBeatTicker:       time.NewTicker(time.Duration(math.MaxInt64)),
	}
	defer c.heartBeatTicker.Stop()

	if err := c.SendHeartbeat(); err != nil {
		t.Fatalf("heartbeat should succeed even when interval omitted: %v", err)
	}
	// 关键：现有心跳间隔不被无意义的重置，上次下发的间隔保持不变
	if c.lastHeartbeatInterval != 90 {
		t.Fatalf("previous interval should be preserved, got %d", c.lastHeartbeatInterval)
	}
}

// --- JS 跳转：非 HTTP 重定向的门户页面应被跟随 ---

func TestAuthFollowsJSRedirect(t *testing.T) {
	c, f := newAuthFixture(t)

	if err := c.Auth(f.base + "/jsredir"); err != nil {
		t.Fatalf("auth via JS-redirect portal failed: %v", err)
	}
	if c.IndexUrl != f.econfigURL() {
		t.Fatalf("expected landing on config page, got %q", c.IndexUrl)
	}
	if !c.authed.Load() {
		t.Fatal("auth should succeed after following JS redirect")
	}
}

// --- 相对 Location 解析 ---

func TestAuthResolvesRelativeLocation(t *testing.T) {
	c, f := newAuthFixture(t)

	// Location: "econfig"（无前导斜杠）应基于 /hoprel/start 解析为 /hoprel/econfig
	if err := c.Auth(f.base + "/hoprel/start"); err != nil {
		t.Fatalf("auth with relative location failed: %v", err)
	}
	if c.IndexUrl != f.base+"/hoprel/econfig" {
		t.Fatalf("relative location not resolved against request URL, got %q", c.IndexUrl)
	}
}

// --- CDC 路由头两种形态（CDC-* 前缀与裸头）均应命中，CDC-* 优先 ---

func TestHarvestCDCSupportsHeaderVariants(t *testing.T) {
	h := http.Header{}
	h.Set("schoolid", "42")       // 裸形态
	h.Set("Cdc-Domain", "gd")     // CDC-* 形态
	h.Set("area", "bare-area")    // 裸形态
	h.Set("Cdc-Area", "cdc-area") // 同一头的 CDC 形态：优先级更高
	resp := &http.Response{Header: h}

	c := &Client{}
	c.harvestCDC(resp)

	if c.SchoolID != "42" || c.Domain != "gd" || c.Area != "cdc-area" {
		t.Fatalf("harvest failed: school=%q domain=%q area=%q", c.SchoolID, c.Domain, c.Area)
	}

	// 超长值必须被钳制
	big := strings.Repeat("x", 4096)
	h2 := http.Header{"Schoolid": []string{big}}
	c.harvestCDC(&http.Response{Header: h2})
	if len(c.SchoolID) != maxCDCHeaderValueLen {
		t.Fatalf("oversized header value should be clamped to %d, got %d", maxCDCHeaderValueLen, len(c.SchoolID))
	}
}

// --- 会话持久化新字段落盘，TryResume 恢复 RedirectUrl 并可继续心跳 ---

func TestSessionRoundTripCarriesNetworkContext(t *testing.T) {
	_, f := newAuthFixture(t)

	var heartbeatUA string
	keepSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		heartbeatUA = r.Header.Get("User-Agent")
		enc, _ := NewCipher(AlgoXTea).Encrypt([]byte(`<response><interval>45</interval></response>`))
		_, _ = w.Write(enc)
	}))
	defer keepSrv.Close()

	dir := t.TempDir()
	sd := &SessionData{
		ClientID:      uuid.NewString(),
		Hostname:      "host1234",
		Mac:           "02:00:5e:aa:bb:cc",
		UserIP:        "10.0.0.9",
		AcIP:          "172.16.0.1",
		AlgoID:        AlgoXTea,
		Ticket:        "tk-1",
		KeepUrl:       keepSrv.URL + "/keep",
		TermUrl:       keepSrv.URL + "/term",
		IndexUrl:      f.econfigURL(),
		RedirectUrl:   f.nextURL(),
		UserAgent:     UAAndroid2089,
		BindInterface: "sys_default",
		DnsAddress:    "",
	}
	if err := SaveSession(dir, "wan0", sd); err != nil {
		t.Fatalf("save session: %v", err)
	}

	loaded, err := LoadSession(dir, "wan0")
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if loaded.RedirectUrl != sd.RedirectUrl || loaded.BindInterface != sd.BindInterface {
		t.Fatalf("network context fields lost across save/load: %+v", loaded)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{
		Config:          &Config{Username: "u", Password: "p"},
		Ctx:             ctx,
		Cancel:          cancel,
		HttpClient:      &http.Client{},
		Log:             nopLogger(),
		heartBeatTicker: time.NewTicker(time.Duration(math.MaxInt64)),
	}
	defer c.heartBeatTicker.Stop()

	if !c.TryResume(loaded) {
		t.Fatal("resume should succeed with reachable keep-url")
	}
	if c.RedirectUrl != sd.RedirectUrl {
		t.Fatalf("redirect url should be restored for later forced re-auth, got %q", c.RedirectUrl)
	}
	if !c.authed.Load() || c.lastHeartbeatInterval != 45 {
		t.Fatalf("resumed session state wrong: authed=%v interval=%d", c.authed.Load(), c.lastHeartbeatInterval)
	}
	// UA 必须随会话持久化并在恢复后沿用（心跳/下线报文与登录会话同族）
	if loaded.UserAgent != UAAndroid2089 {
		t.Fatalf("user_agent lost across save/load, got %q", loaded.UserAgent)
	}
	if c.currentUA() != UAAndroid2089 {
		t.Fatalf("resumed client must reuse login ua, got %q", c.currentUA())
	}
	if heartbeatUA != UAAndroid2089 {
		t.Fatalf("heartbeat request must carry login ua, got %q", heartbeatUA)
	}
}

// --- 24 算法全链路闭环（mock portal 参数化，Phase D）---

func TestAuthFullFlowAllAlgorithms(t *testing.T) {
	for _, id := range allRegisteredAlgoIDs() {
		id := id
		t.Run(id[:8], func(t *testing.T) {
			c, f := newAuthFixture(t)
			f.algoID = id

			if err := c.Auth(f.nextURL()); err != nil {
				t.Fatalf("auth flow failed with algo %s: %v", id, err)
			}
			if c.AlgoID != id {
				t.Fatalf("negotiated algo %q != mock-served %q", c.AlgoID, id)
			}
			if c.Ticket != "tkt-123" {
				t.Fatalf("expected ticket tkt-123, got %q", c.Ticket)
			}
			if !c.authed.Load() {
				t.Fatal("authed should be true")
			}
		})
	}
}

// --- UA 回退链：被拒 UA 自动换下一个，成功值记忆且重认证不再重复试探 ---

func TestAuthUAFallbackAndPreferredMemory(t *testing.T) {
	c, f := newAuthFixture(t)
	// 模拟本校 09-02 实测形态：2104 被准入闸拒（Error-Code 3），2089 放行
	f.rejectUAs = map[string]string{UAAndroid2104: "3"}

	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("auth should fall back to next ua: %v", err)
	}
	if got := c.currentUA(); got != UAAndroid2089 {
		t.Fatalf("expected fallback to %s, got %q", UAAndroid2089, got)
	}
	if !c.authed.Load() {
		t.Fatal("authed should be true after fallback")
	}
	if f.uaCount(UAAndroid2104) != 1 || f.uaCount(UAAndroid2089) != 1 {
		t.Fatalf("expected exactly one handshake per tried ua, got 2104=%d 2089=%d",
			f.uaCount(UAAndroid2104), f.uaCount(UAAndroid2089))
	}

	// 重认证（黑洞自愈路径）：preferredUA 置链首，不得再试探已知被拒的 2104
	c.authed.Store(false)
	if err := c.HandleRedirect(nil); err != nil {
		t.Fatalf("re-auth should reuse preferred ua: %v", err)
	}
	if f.uaCount(UAAndroid2104) != 1 {
		t.Fatalf("preferred ua must not retry known-bad 2104 (handshakes=%d)", f.uaCount(UAAndroid2104))
	}
	if f.uaCount(UAAndroid2089) != 2 {
		t.Fatalf("re-auth should handshake with 2089 again (handshakes=%d)", f.uaCount(UAAndroid2089))
	}
}

// --- 链耗尽：错误信息必须列出全部 UA 尝试记录 ---

func TestAuthAllUAsRejected(t *testing.T) {
	c, f := newAuthFixture(t)
	f.rejectUAs = map[string]string{
		UAAndroid2104: "3",
		UAAndroid2089: "3",
		UAAndroid2093: "3",
	}

	err := c.Auth(f.nextURL())
	if err == nil {
		t.Fatal("auth must fail when every ua in chain is rejected")
	}
	msg := err.Error()
	for _, ua := range []string{UAAndroid2104, UAAndroid2089, UAAndroid2093} {
		if !strings.Contains(msg, ua) {
			t.Fatalf("error should list attempt for %s, got: %s", ua, msg)
		}
	}
	if !strings.Contains(msg, "error_code=3") {
		t.Fatalf("error should carry error_code diagnostics, got: %s", msg)
	}
	if c.authed.Load() {
		t.Fatal("authed must stay false")
	}
}

// --- 未知 GUID：触发回退换下一个 UA（第四代兑底语义）---

func TestAuthUnknownGUIDFallsBack(t *testing.T) {
	c, f := newAuthFixture(t)
	unknown := "376412D4-0000-0000-0000-000000000000" // Windows 族未知 GUID（uaprobe 实测形态）
	f.algoForUA = func(ua string) string {
		if ua == UAAndroid2104 {
			return unknown
		}
		return "" // 其余 UA → f.algoID（XTEA）
	}

	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("unknown guid should fall back to next ua: %v", err)
	}
	if c.AlgoID != AlgoXTea {
		t.Fatalf("expected fallback to known algo, got %q", c.AlgoID)
	}
	if f.uaCount(UAAndroid2104) != 1 {
		t.Fatalf("2104 should be tried exactly once (handshakes=%d)", f.uaCount(UAAndroid2104))
	}
}

// --- ZSM 握手 body 必须每次归零：重认证不得带上次 GUID（Error-Code 1，docs/05 §3.2）---

func TestAuthAlgoIDResetsOnReauth(t *testing.T) {
	c, f := newAuthFixture(t)

	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("initial auth failed: %v", err)
	}
	if c.AlgoID != AlgoXTea {
		t.Fatalf("expected negotiated %q, got %q", AlgoXTea, c.AlgoID)
	}

	// 强制重认证：第二次 ZSM 握手 body 必须仍是全零 UUID 而非 AlgoXTea
	c.authed.Store(false)
	if err := c.HandleRedirect(nil); err != nil {
		t.Fatalf("re-auth failed: %v", err)
	}

	handshakes := f.zsmHandshakes()
	if len(handshakes) != 2 {
		t.Fatalf("expected 2 zsm handshakes, got %d", len(handshakes))
	}
	for i, hs := range handshakes {
		if string(hs.body) != "00000000-0000-0000-0000-000000000000" {
			t.Fatalf("zsm handshake #%d body must be zero uuid, got %q", i, string(hs.body))
		}
	}
}

// --- 自选 UA：HTTP 头与 XML <user-agent> 报文体同源 ---

func TestAuthSingleUAContract(t *testing.T) {
	c, f := newAuthFixture(t)
	c.Config.UserAgent = UAAndroid2089

	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("auth with configured ua failed: %v", err)
	}
	if got := c.currentUA(); got != UAAndroid2089 {
		t.Fatalf("currentUA should be configured value, got %q", got)
	}

	// 所有捕获的请求（门户 GET + 业务 POST）都必须携带同一 UA
	reqs := f.requestsByPath("/portal")
	reqs = append(reqs, f.requestsByPath("/econfig")...)
	reqs = append(reqs, f.requestsByPath("/ticket")...)
	reqs = append(reqs, f.requestsByPath("/auth")...)
	if len(reqs) == 0 {
		t.Fatal("no captured requests")
	}
	for _, r := range reqs {
		if r.ua != UAAndroid2089 {
			t.Fatalf("request %s %s carried ua %q, want %q", r.method, r.path, r.ua, UAAndroid2089)
		}
	}

	// 加密报文体中的 <user-agent> 字段与 HTTP 头同源
	f.mu.Lock()
	plain := f.lastTicketPlain
	f.mu.Unlock()
	if !strings.Contains(plain, "<user-agent>"+UAAndroid2089+"</user-agent>") {
		t.Fatalf("ticket xml user-agent mismatch, body: %s", plain)
	}
}

// --- Error-Code 头缺失（mock/老门户形态）必须视为成功 ---

func TestAuthMissingErrorCodeHeaderStillSucceeds(t *testing.T) {
	c, f := newAuthFixture(t)
	f.omitZSMErrorCode = true

	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("missing Error-Code header must not be treated as rejection: %v", err)
	}
	if !c.authed.Load() {
		t.Fatal("authed should be true")
	}
}
