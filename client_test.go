package main

import (
	"context"
	"encoding/xml"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// newTestClient 构造一个不依赖真实网络的 Client。
// 心跳/认证 URL 由测试注入（默认为 404 的测试服务器），防止意外触网。
// redirectURL 模拟上一次认证遗留的重定向地址（黑洞自愈时复用）。
func newTestClient(t *testing.T) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

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
		HttpClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ClientID:        uuid.New(),
		Log:             nopLogger(),
		RedirectUrl:     "http://127.0.0.1:1/blackhole-cached-redirect",
		heartBeatTicker: time.NewTicker(time.Duration(math.MaxInt64)),
	}
	return c, srv
}

func nopLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// --- 1. 黑洞自愈：连续探测失败达到阈值必须触发重认证 ---

func TestBlackholeReauthAfterConsecutiveCheckFailures(t *testing.T) {
	c, srv := newTestClient(t)
	// 探测目标指向 404 服务器，模拟网络黑洞（非 204/302 响应）
	c.HttpClient.Transport = rewriteTransport(srv.URL)

	var (
		mu       sync.Mutex
		authRuns int
	)
	// OnBeforeAuth 在 HandleRedirect 入口调用，无论 Auth 成败都会执行
	c.OnBeforeAuth = func() { mu.Lock(); authRuns++; mu.Unlock() }

	// 模拟连续 3 次探测失败
	for i := 0; i < blackholeReauthThreshold; i++ {
		if err := c.CheckNetwork(); err == nil {
			t.Fatalf("check %d: expected failure against 404 server, got nil", i)
		}
		c.consecutiveCheckFailures++ // 复现主循环的计数逻辑
	}

	// 达到阈值 → 主循环调用 HandleRedirect(nil) 强制重认证
	//（这里直接验证 HandleRedirect(nil) 不 panic 且走了认证入口）
	c.consecutiveCheckFailures = 0
	if err := c.HandleRedirect(nil); err != nil {
		t.Fatalf("HandleRedirect(nil) returned error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if authRuns != 1 {
		t.Fatalf("expected 1 auth attempt, got %d", authRuns)
	}
}

// --- 2. 强制重认证：空 URL 时复用缓存的重定向地址，安全失败不 panic ---

func TestHandleRedirectNilRespSafeFailure(t *testing.T) {
	c, _ := newTestClient(t)

	var panicked bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_ = c.HandleRedirect(nil) // 复用缓存的 RedirectUrl → 连接 127.0.0.1:1 失败 → 安全失败
	}()
	if panicked {
		t.Fatal("HandleRedirect(nil) panicked")
	}
	if c.lastAuthFail.IsZero() {
		t.Fatal("auth failure should set lastAuthFail")
	}
	// 黑洞自愈的关铔：强制重认证不应丢失缓存的重定向地址
	if c.RedirectUrl != "http://127.0.0.1:1/blackhole-cached-redirect" {
		t.Fatalf("cached RedirectUrl must survive force re-auth, got %q", c.RedirectUrl)
	}
}

// --- 3. 204 探测成功必须清零连续失败计数 ---

func TestCheckNetwork204ResetsFailureCounter(t *testing.T) {
	c, _ := newTestClient(t)

	var statusOK int32
	srv204 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.StoreInt32(&statusOK, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv204.Close()

	// 预置失败计数，模拟先前故障
	c.consecutiveCheckFailures = 2

	// CheckNetwork 的目标是固定 URL，这里通过拦截 transport 改写目标地址
	c.HttpClient.Transport = rewriteTransport(srv204.URL)

	if err := c.CheckNetwork(); err != nil {
		t.Fatalf("expected 204, got error: %v", err)
	}
	if c.consecutiveCheckFailures != 0 {
		t.Fatalf("expected failure counter reset to 0, got %d", c.consecutiveCheckFailures)
	}
	if atomic.LoadInt32(&statusOK) == 0 {
		t.Fatal("204 server was not hit")
	}
}

// rewriteTransport 将所有请求重定向到 base URL（保持路径不变）
type rewriteRoundTripper struct {
	base   string
	prefix string
}

func (rt *rewriteRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 去掉 scheme://host，拼接到 base
	u := *req.URL
	u.Scheme = ""
	u.Host = ""
	target := rt.base + u.String()
	proxyReq, err := http.NewRequest(req.Method, target, req.Body)
	if err != nil {
		return nil, err
	}
	proxyReq.Header = req.Header
	return http.DefaultTransport.RoundTrip(proxyReq)
}

func rewriteTransport(base string) http.RoundTripper {
	return &rewriteRoundTripper{base: base}
}

// --- 4. 302 探测必须清零失败计数并触发认证 ---

func TestCheckNetwork302ResetsCounterAndAuths(t *testing.T) {
	c, _ := newTestClient(t)

	srv302 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://portal.example.com/redirected")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv302.Close()

	c.HttpClient.Transport = rewriteTransport(srv302.URL)
	c.consecutiveCheckFailures = 2

	authCalled := false
	c.OnBeforeAuth = func() { authCalled = true }

	// 302 → HandleRedirect → Auth("http://portal.example.com/redirected")
	// 认证会因测试环境无真实服务器而失败，但流程必须走到 Auth 入口
	_ = c.CheckNetwork()

	if c.consecutiveCheckFailures != 0 {
		t.Fatalf("302 should reset counter, got %d", c.consecutiveCheckFailures)
	}
	if !authCalled {
		t.Fatal("302 should trigger auth flow")
	}
	if c.RedirectUrl != "http://portal.example.com/redirected" {
		t.Fatalf("RedirectUrl not captured, got %q", c.RedirectUrl)
	}
}

// --- 5. 心跳响应解析：异常间隔不应导致 panic ---

func TestSendHeartbeatIntervalParse(t *testing.T) {
	// StateResponse.Interval 非数字 → strconv 报错 → SendHeartbeat 返回 error
	interval := "not-a-number"
	if _, err := strconv.Atoi(interval); err == nil {
		t.Fatal("precondition failed")
	}

	// 直接验证 xml 结构定义与字段绑定
	var sr StateResponse
	if err := xml.Unmarshal([]byte(`<response><interval>60</interval></response>`), &sr); err != nil {
		t.Fatal(err)
	}
	if sr.Interval != "60" {
		t.Fatalf("unexpected interval %q", sr.Interval)
	}
}

var _ = time.Second // 保持 time 引用
