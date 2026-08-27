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
	f := &authFixture{}

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
					_, _ = w.Write(buildAlgoIDPayload())
					return
				}
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

	mu       sync.Mutex
	captured []capturedRequest
}

func (f *authFixture) record(r *http.Request, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.captured = append(f.captured, capturedRequest{
		method:      r.Method,
		path:        r.URL.Path,
		contentType: r.Header.Get("Content-Type"),
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

// cipher 使用固定算法 ID（XTEA 纯软件实现，无平台差异）
func (f *authFixture) cipher() Cipher { return NewCipher(AlgoXTea) }

func mustUUID() uuid.UUID { return uuid.New() }

// xmlEsc 将 URL 中的 XML 特殊字符转义
func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// buildAlgoIDPayload 构造 ZSM 握手响应的二进制结构：
// [4字节头 byte[3]=keyLen] [key] ['$'] [36字节算法ID]（分隔符值 0x24 恰为 36）
func buildAlgoIDPayload() []byte {
	algoID := []byte(AlgoXTea)
	key := []byte("testkey")
	out := []byte{0, 0, 0, byte(len(key))}
	out = append(out, key...)
	out = append(out, '$')
	out = append(out, algoID...)
	return out
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

	keepSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}
