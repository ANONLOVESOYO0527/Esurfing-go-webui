package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// newAuthFixture 构造一个完整的认证链路模拟环境：
// 重定向服务器(302) → 学校信息服务器(302+headers) → 配置页服务器(嵌入配置的HTML)
// 算法ID服务器(二进制) → 票据服务器(加密XML) → 登录服务器(加密XML)
// 加密层用真实 cipher（对测试透明），仅模拟网络层。
func newAuthFixture(t *testing.T) (*Client, *authFixture) {
	t.Helper()
	f := &authFixture{}

	// 登录响应：keep-retry=60，keep/term URL 指向可达的服务器
	loginSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(loginSrv.Close)

	// 各阶段按序访问：school → econfig → algo → ticket → login
	// 通过独立的 handler 记录调用顺序
	var mu sync.Mutex
	stage := 0

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		// 每轮认证链从 /portal 入口（GetSchoolInfo）开始，重置阶段计数
		if r.URL.Path == "/portal" {
			stage = 0
		}
		stage++
		switch stage {
		case 1: // GetSchoolInfo
			w.Header().Set("domain", "gd")
			w.Header().Set("area", "area1")
			w.Header().Set("schoolid", "1234")
			w.Header().Set("Location", f.econfigURL()) // econfig 页
			w.WriteHeader(http.StatusFound)
		case 2: // GetEConfig
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!--//config.campus.js.chinatelecom.com ` +
				`<config><ticket-url>` + xmlEsc(f.ticketURL()) + `</ticket-url><auth-url>` + xmlEsc(f.ticketURL()) + `</auth-url></config>` +
				`//config.campus.js.chinatelecom.com-->`))
		case 3: // GetAlgoId（POST，返回二进制 algo-id）
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(buildAlgoIDPayload())
		case 4: // GetTicket（POST XML，加密）
			w.WriteHeader(http.StatusOK)
			enc, _ := f.cipher().Encrypt([]byte(`<?xml version="1.0"?><response><ticket>tkt-123</ticket></response>`))
			_, _ = w.Write(enc)
		case 5: // Login（POST XML，加密）
			w.WriteHeader(http.StatusOK)
			enc, _ := f.cipher().Encrypt([]byte(`<?xml version="1.0"?><response><userid>u</userid>` +
				`<keep-retry>60</keep-retry><keep-url>` + loginSrv.URL + `/keep.cgi</keep-url>` +
				`<term-url>` + loginSrv.URL + `/term.cgi</term-url></response>`))
			_, _ = w.Write(enc)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(redirectSrv.Close)

	f.base = redirectSrv.URL
	f.loginBase = loginSrv.URL

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
		ClientID:        mustUUID(),
		Log:             nopLogger(),
		heartBeatTicker: time.NewTicker(time.Duration(1) << 62),
	}
	return c, f
}

type authFixture struct {
	base      string
	loginBase string
}

// nextURL 返回配置页地址（与 ticket 地址相同，由 stage 区分）
func (f *authFixture) nextURL() string { return f.base + "/portal" }

// econfigURL 认证页配置地址（GetSchoolInfo 的 Location 目标）
func (f *authFixture) econfigURL() string { return f.base + "/econfig" }
func (f *authFixture) ticketURL() string {
	return f.base + "/ticket?wlanuserip=10.0.0.1&wlanacip=10.0.0.2"
}

// cipher 使用固定算法 ID（XTEA 纯软件实现，无平台差异）
func (f *authFixture) cipher() Cipher { return NewCipher(AlgoXTea) }

func mustUUID() uuid.UUID { return uuid.New() }

// xmlEsc 将 URL 中的 XML 特殊字符转义
func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// buildAlgoIDPayload 构造 GetAlgoId 响应的二进制结构：[3]=keyLen, key, [0]=algoLen, algoID
func buildAlgoIDPayload() []byte {
	algoID := []byte(AlgoXTea)
	key := []byte("testkey")
	out := []byte{0, 0, 0, byte(len(key))}
	out = append(out, key...)
	out = append(out, byte(len(algoID)))
	out = append(out, algoID...)
	return out
}

// --- 6. 完整认证链路集成测试：模拟真实认证流程走通 ---

func TestAuthFullFlow(t *testing.T) {
	c, f := newAuthFixture(t)

	// 完整认证：从重定向 URL 开始
	err := c.Auth(f.nextURL())
	if err != nil {
		t.Fatalf("auth flow failed: %v", err)
	}

	if c.Ticket != "tkt-123" {
		t.Fatalf("expected ticket tkt-123, got %q", c.Ticket)
	}
	if c.KeepUrl != f.loginBase+"/keep.cgi" {
		t.Fatalf("unexpected KeepUrl %q", c.KeepUrl)
	}
	if !c.authed.Load() {
		t.Fatal("authed should be true after successful auth")
	}
}

// --- 7. 黑洞自愈集成：强制重认证复用缓存的 RedirectUrl ---

func TestBlackholeForceReauthReusesCachedRedirect(t *testing.T) {
	c, f := newAuthFixture(t)

	// 第一次认证成功，缓存 RedirectUrl
	if err := c.Auth(f.nextURL()); err != nil {
		t.Fatalf("initial auth failed: %v", err)
	}
	c.authed.Store(false)
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
