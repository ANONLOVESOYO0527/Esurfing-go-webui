package main

import (
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- 黑洞自愈探测 transport 工具 ---

// dnsFailRoundTripper 对指定 host 的请求模拟 DNS 解析失败（认证失效时校园网
// 连带切断 DNS 的典型形态），其余请求转发给 next。
type dnsFailRoundTripper struct {
	host string
	next http.RoundTripper
}

func (rt *dnsFailRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() == rt.host {
		return nil, &net.DNSError{Err: "i/o timeout", Name: req.URL.Hostname(), IsTimeout: true, IsTemporary: true}
	}
	if rt.next == nil {
		return nil, errors.New("no next transport")
	}
	return rt.next.RoundTrip(req)
}

// failingRoundTripper 一切请求都失败（模拟真黑洞）。
type failingRoundTripper struct{ err error }

func (rt *failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, rt.err
}

const testCheckHost = "connect.rom.miui.com"

// --- 1. DNS 黑洞 + 探针被劫持 302 → 必须取 Location 进入认证链 ---

func TestCheckNetworkDNSFallbackHijack302(t *testing.T) {
	c, _ := newTestClient(t)
	entry := "http://portal.test/entry?wlanuserip=10.0.0.1&wlanacip=2"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", entry)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	c.HttpClient.Transport = &dnsFailRoundTripper{host: testCheckHost, next: rewriteTransport(srv.URL)}

	var authCalled atomic.Bool
	c.OnBeforeAuth = func() { authCalled.Store(true) }

	if err := c.CheckNetwork(); err != nil {
		t.Fatalf("expected nil error (302 branch returns HandleRedirect result), got %v", err)
	}
	if !authCalled.Load() {
		t.Fatal("hijacked probe must trigger auth flow")
	}
	if c.RedirectUrl != entry {
		t.Fatalf("portal entry not captured from probe Location, got %q", c.RedirectUrl)
	}
	if c.consecutiveCheckFailures != 0 {
		t.Fatalf("302 should reset check counter, got %d", c.consecutiveCheckFailures)
	}
	// 测试环境认证链必然失败（门户循环重定向），失败必须计入退避状态
	if c.lastAuthFail.IsZero() {
		t.Fatal("auth failure should be recorded")
	}
	if c.consecutiveAuthFails != 1 {
		t.Fatalf("expected 1 consecutive auth failure, got %d", c.consecutiveAuthFails)
	}
}

// --- 2. DNS 黑洞 + 探针可达未劫持（仅 DNS 受损）→ 视为在线，不计失败 ---

func TestCheckNetworkDNSFallbackAliveNotHijacked(t *testing.T) {
	c, _ := newTestClient(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c.HttpClient.Transport = &dnsFailRoundTripper{host: testCheckHost, next: rewriteTransport(srv.URL)}
	c.consecutiveCheckFailures = 2
	c.lastAuthFail = time.Now()
	c.consecutiveAuthFails = 3

	if err := c.CheckNetwork(); err != nil {
		t.Fatalf("reachable-but-not-hijacked probe must be treated as online, got %v", err)
	}
	if c.consecutiveCheckFailures != 0 {
		t.Fatalf("counter must reset, got %d", c.consecutiveCheckFailures)
	}
	// 关键回归约束：在线态不得清认证退避状态——否则会话丢失时的重认领会
	// 退化为每 tick 一次的高频重认证风暴（review 发现的缺陷）
	if c.lastAuthFail.IsZero() || c.consecutiveAuthFails != 3 {
		t.Fatal("online state must NOT clear auth backoff state")
	}
}

// --- 3. DNS 黑洞 + 探针全部不可达 → 真黑洞，返回错误交调用方计数 ---

func TestCheckNetworkDNSFallbackAllProbesFail(t *testing.T) {
	c, _ := newTestClient(t)

	c.HttpClient.Transport = &dnsFailRoundTripper{
		host: testCheckHost,
		next: &failingRoundTripper{err: errors.New("dial: connection refused")},
	}

	err := c.CheckNetwork()
	if err == nil {
		t.Fatal("expected error when all probes unreachable")
	}
	if !strings.Contains(err.Error(), "dns-free probes also failed") {
		t.Fatalf("error should mention probe failure, got %v", err)
	}
}

// --- 4. 强制重认证无缓存入口 → 探针 302 发现门户入口（原 bug：秒败 missing redirect URL）---

func TestForceReauthDiscoversEntryFromProbeRedirect(t *testing.T) {
	c, _ := newTestClient(t)
	c.RedirectUrl = "" // 模拟从未认证成功的全新 client

	entry := "http://portal.test/entry?wlanuserip=10.0.0.1&wlanacip=2"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", entry)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	c.HttpClient.Transport = rewriteTransport(srv.URL)

	err := c.Auth("")
	if err != nil {
		if strings.Contains(err.Error(), "missing redirect URL") {
			t.Fatalf("discovery must provide an entry before auth chain runs, got %v", err)
		}
		// 入口已发现，认证链在测试环境因门户循环重定向而失败——符合预期
		if !strings.Contains(err.Error(), "too many redirects") {
			t.Fatalf("unexpected auth error: %v", err)
		}
	}
	if c.RedirectUrl != entry {
		t.Fatalf("entry not discovered, got %q", c.RedirectUrl)
	}
}

// --- 5. 探针不可达但持有上次会话门户地址 → 兑底入口为门户基址 ---

func TestForceReauthWithoutCacheFallsBackToPortalBase(t *testing.T) {
	c, _ := newTestClient(t)
	c.RedirectUrl = ""
	c.KeepUrl = "http://10.1.2.3:7001/keep.cgi"
	c.TermUrl = "http://10.1.2.3:7001/term.cgi"

	c.HttpClient.Transport = &failingRoundTripper{err: errors.New("dial: connection refused")}

	err := c.Auth("")
	if err == nil {
		t.Fatal("auth must fail against unreachable portal in test env")
	}
	if strings.Contains(err.Error(), "missing redirect URL") {
		t.Fatalf("portal base fallback should provide entry, got %v", err)
	}
	if want := "http://10.1.2.3:7001/"; c.RedirectUrl != want {
		t.Fatalf("portal base entry expected %q, got %q", want, c.RedirectUrl)
	}
}

// --- 6. 全部手段失败 → 报 missing redirect URL（回归守卫：明确失败而非 panic/静默）---

func TestForceReauthWithoutCacheStillFailsCleanly(t *testing.T) {
	c, _ := newTestClient(t)
	c.RedirectUrl = ""
	c.KeepUrl, c.TermUrl, c.IndexUrl = "", "", ""

	c.HttpClient.Transport = &failingRoundTripper{err: errors.New("dial: connection refused")}

	err := c.Auth("")
	if err == nil || !strings.Contains(err.Error(), "missing redirect URL") {
		t.Fatalf("expected missing redirect URL failure, got %v", err)
	}
}

// --- 7. 认证退避：连续失败指数增长，封顶 16 倍 ---

func TestAuthBackoffGrowthAndCap(t *testing.T) {
	c, _ := newTestClient(t)
	c.Config.RetryInterval = 10000 // 10s

	cases := []struct {
		fails int
		want  time.Duration
	}{
		{0, 10 * time.Second},
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 40 * time.Second},
		{4, 80 * time.Second},
		{5, 160 * time.Second},
		{9, 160 * time.Second}, // 封顶
	}
	for _, tc := range cases {
		c.consecutiveAuthFails = tc.fails
		if got := c.authBackoff(); got != tc.want {
			t.Fatalf("fails=%d: backoff = %v, want %v", tc.fails, got, tc.want)
		}
	}

	// RetryIntervalNever（NewClient 归一为 MaxInt32 ms）位移不得溢出
	c.Config.RetryInterval = math.MaxInt32
	c.consecutiveAuthFails = 9
	if got := c.authBackoff(); got <= 0 {
		t.Fatalf("backoff overflowed: %v", got)
	}
}

// --- 8. 204 恢复：会话字段完好但心跳被暂停 → 重启心跳，不触发重认证 ---

func TestOnline204ResumesHeartbeatOfIntactSession(t *testing.T) {
	c, _ := newTestClient(t)

	srv204 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv204.Close()
	c.HttpClient.Transport = rewriteTransport(srv204.URL)

	c.authed.Store(true)
	c.KeepUrl = "http://10.1.2.3:7001/keep.cgi"
	c.heartbeatPaused = true
	c.lastHeartbeatInterval = 300

	var authCalled atomic.Bool
	c.OnBeforeAuth = func() { authCalled.Store(true) }

	if err := c.CheckNetwork(); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if c.heartbeatPaused {
		t.Fatal("heartbeat must be resumed for intact session")
	}
	if authCalled.Load() {
		t.Fatal("intact session must not trigger re-auth")
	}
}

// --- 9. 204 恢复：会话字段已被失败的重认证清空 → 主动重新认领会话 ---

func TestOnline204ReadoptsLostSession(t *testing.T) {
	c, _ := newTestClient(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c.HttpClient.Transport = rewriteTransport(srv.URL)

	c.authed.Store(true)
	c.KeepUrl = "" // 强制重认证失败后 resetSession 清空了会话字段

	var authCalled atomic.Bool
	c.OnBeforeAuth = func() { authCalled.Store(true) }

	if err := c.CheckNetwork(); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if !authCalled.Load() {
		t.Fatal("lost session state must trigger re-adopt attempt")
	}
	if c.lastAuthFail.IsZero() {
		t.Fatal("failed re-adopt should be recorded as auth failure")
	}
	if !c.authed.Load() {
		t.Fatal("authed flag must survive failed re-adopt")
	}
}

// --- 10. 204 恢复：从未认证的监控态 client → 不动作 ---

func TestOnline204SkipsRecoverForFreshClient(t *testing.T) {
	c, _ := newTestClient(t)

	srv204 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv204.Close()
	c.HttpClient.Transport = rewriteTransport(srv204.URL)

	var authCalled atomic.Bool
	c.OnBeforeAuth = func() { authCalled.Store(true) }

	if err := c.CheckNetwork(); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if authCalled.Load() {
		t.Fatal("fresh client must stay in monitor mode")
	}
}

// --- 11. portalBaseOf：提取门户基址 ---

func TestPortalBaseOf(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"http://14.146.227.142:7001/keep.cgi", "http://14.146.227.141:7001/term.cgi"}, "http://14.146.227.142:7001/"},
		{[]string{"", "http://10.0.0.1/term.cgi"}, "http://10.0.0.1/"},
		{[]string{"", "", ""}, ""},
		{[]string{"::::not-a-url"}, ""},
		{[]string{"/relative/only"}, ""},
	}
	for i, tc := range cases {
		if got := portalBaseOf(tc.in...); got != tc.want {
			t.Fatalf("case %d: portalBaseOf(%v) = %q, want %q", i, tc.in, got, tc.want)
		}
	}
}

// --- 12. 心跳失败计数独立于网络检查（事故 13:09/13:29/13:34 的根因回归测试）---

func TestHeartbeatFailureCounterIndependentOfCheckSuccess(t *testing.T) {
	c, _ := newTestClient(t)

	// 网络检查成功（204），但心跳持续失败：复刻事故日志形态
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c.HttpClient.Transport = rewriteTransport(srv.URL)

	authRuns := 0
	c.OnBeforeAuth = func() { authRuns++ }

	// 三次心跳失败，每次失败后的 recheck 都成功（204）
	for i := 1; i <= 3; i++ {
		c.onHeartbeatError(errors.New("dial tcp 14.146.227.142:7001: i/o timeout"))
		if i < 3 {
			// 共享计数器缺陷形态：成功的 recheck 曾把心跳失败计数清零，阈值永远到不了
			if c.consecutiveHeartbeatFails != i {
				t.Fatalf("after %d heartbeat failures, counter must be %d (successful recheck must NOT reset), got %d",
					i, i, c.consecutiveHeartbeatFails)
			}
		}
	}
	if authRuns != 1 {
		t.Fatalf("3 consecutive heartbeat failures must trigger exactly 1 forced re-auth, got %d", authRuns)
	}
	if c.consecutiveHeartbeatFails != 0 {
		t.Fatalf("counter must reset after threshold trigger, got %d", c.consecutiveHeartbeatFails)
	}
	if !c.heartbeatPaused {
		t.Fatal("heartbeat must be paused before forced re-auth")
	}
	if c.lastAuthFail.IsZero() {
		t.Fatal("failed forced re-auth must be recorded for backoff")
	}
}

// --- 13. 在线态不清退避：重认领失败的退避计数必须跨 204 检查累积 ---

func TestOnline204ReadoptRespectsBackoff(t *testing.T) {
	c, _ := newTestClient(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/generate_204" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound) // 门户页不可达 → 认证链失败
	}))
	defer srv.Close()
	c.HttpClient.Transport = rewriteTransport(srv.URL)

	c.authed.Store(true)
	c.KeepUrl = "" // 会话状态被失败的强制重认证清空

	authRuns := 0
	c.OnBeforeAuth = func() { authRuns++ }

	for i := 1; i <= 3; i++ {
		if err := c.CheckNetwork(); err != nil {
			t.Fatalf("check %d: expected nil (204), got %v", i, err)
		}
		if authRuns != i {
			t.Fatalf("re-adopt must fire on gate-passing tick %d, got %d runs", i, authRuns)
		}
		if c.consecutiveAuthFails != i {
			t.Fatalf("backoff counter must accumulate across 204 checks (not cleared), got %d after %d failures",
				c.consecutiveAuthFails, i)
		}
	}
	// 3 次失败 → 退避应为基间隔 ×4（10s × 2^2）
	if got := c.authBackoff(); got != 40*time.Second {
		t.Fatalf("backoff after 3 failures = %v, want 40s", got)
	}
}

// hostRouteTransport 按 host 精确路由（探针 host → 劫持模拟服务器，其余直连）
type hostRouteTransport struct {
	routes map[string]string
}

func (rt *hostRouteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if target, ok := rt.routes[req.URL.Host]; ok {
		u := *req.URL
		u.Scheme = ""
		u.Host = ""
		proxyReq, err := http.NewRequest(req.Method, target+u.String(), nil)
		if err != nil {
			return nil, err
		}
		proxyReq.Header = req.Header
		return http.DefaultTransport.RoundTrip(proxyReq)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// --- 14. 端到端：全新 client + DNS 黑洞 + 探针劫持 302 → 入口发现 → 完整认证成功 ---

func TestBlackholeRecoveryEndToEnd(t *testing.T) {
	c, f := newAuthFixture(t)
	c.RedirectUrl = "" // 全新 client：无缓存入口（enable-during-blackhole 场景）

	// 劫持模拟：公共探针被 BRAS 302 到门户入口
	hijackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", f.base+"/portal")
		w.WriteHeader(http.StatusFound)
	}))
	defer hijackSrv.Close()

	routes := map[string]string{}
	for _, u := range fallbackProbeURLs {
		if pu, perr := url.Parse(u); perr == nil {
			routes[pu.Host] = hijackSrv.URL
		}
	}
	c.HttpClient.Transport = &hostRouteTransport{routes: routes}

	// 黑洞自愈路径：无缓存入口 → DNS 无关探针发现门户 → 完整认证链
	if err := c.Auth(""); err != nil {
		t.Fatalf("blackhole recovery failed: %v", err)
	}
	if !c.authed.Load() {
		t.Fatal("client must be authed after blackhole recovery")
	}
	if c.RedirectUrl != f.base+"/portal" {
		t.Fatalf("portal entry not discovered from hijacked probe, got %q", c.RedirectUrl)
	}
	if !strings.Contains(c.KeepUrl, "keep.cgi") {
		t.Fatalf("KeepUrl not set after recovery, got %q", c.KeepUrl)
	}
	if c.consecutiveAuthFails != 0 || !c.lastAuthFail.IsZero() {
		t.Fatalf("auth success must reset backoff state, got fails=%d", c.consecutiveAuthFails)
	}
}
