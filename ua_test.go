// ua_test.go — UA 配置与回退链单元测试（Phase D）
package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestValidUserAgent 配置校验：非法 UA（含空白/控制字符/超长）必须被拒
func TestValidUserAgent(t *testing.T) {
	valid := []string{
		"",             // 空 = 自动链（缺省）
		"auto", "AUTO", // 自动链（大小写不敏感）
		UAAndroid2104, UAAndroid2089, UAAndroid2093, UAPCLinux64,
		"CCTP/WinSVR5/1068", // 自定义 UA（uaprobe 实测可准入的 Windows 族）
		"CCTP/macdy/10087",  // 自定义 UA（Mac 族）
	}
	invalid := []string{
		"CCTP android/1",        // 空白（UA 会进入 HTTP 头与 XML 体，空白可造成头注入/报文损坏）
		"a\tb",                  // 制表符
		"a\nb",                  // 换行
		"a\x00b",                // NUL 控制字符
		strings.Repeat("x", 65), // 超长（>64，门户准入闸可能拒绝）
	}
	for _, ua := range valid {
		if !validUserAgent(ua) {
			t.Fatalf("validUserAgent(%q) must be true", ua)
		}
	}
	for _, ua := range invalid {
		if validUserAgent(ua) {
			t.Fatalf("validUserAgent(%q) must be false", ua)
		}
	}
}

// TestResolveUAChain 链解析：auto → 默认链 + preferredUA 置首；自选 → 单元素链
func TestResolveUAChain(t *testing.T) {
	// auto（缺省）：默认链 [2104→2089→2093]
	c := &Client{Config: &Config{}}
	c.resolveUAChain()
	want := []string{UAAndroid2104, UAAndroid2089, UAAndroid2093}
	if len(c.uaChain) != len(want) {
		t.Fatalf("auto chain length = %d, want %d", len(c.uaChain), len(want))
	}
	for i := range want {
		if c.uaChain[i] != want[i] {
			t.Fatalf("auto chain[%d] = %q, want %q", i, c.uaChain[i], want[i])
		}
	}

	// auto + preferredUA：上次成功值置链首且不重复
	c.preferredUA = UAAndroid2089
	c.resolveUAChain()
	if c.uaChain[0] != UAAndroid2089 {
		t.Fatalf("preferred ua must be chain head, got %q", c.uaChain[0])
	}
	if len(c.uaChain) != 3 {
		t.Fatalf("chain must stay length 3 after dedup, got %d", len(c.uaChain))
	}

	// 自选 UA：单元素链，不做回退
	c2 := &Client{Config: &Config{UserAgent: UAPCLinux64}}
	c2.resolveUAChain()
	if len(c2.uaChain) != 1 || c2.uaChain[0] != UAPCLinux64 {
		t.Fatalf("explicit ua must yield single-element chain, got %v", c2.uaChain)
	}
	// 自选时 preferredUA 不参与（用户显式配置优先）
	c2.preferredUA = UAAndroid2104
	c2.resolveUAChain()
	if len(c2.uaChain) != 1 || c2.uaChain[0] != UAPCLinux64 {
		t.Fatalf("explicit ua must override preferred memory, got %v", c2.uaChain)
	}

	// "auto" 显式配置 = 缺省
	c3 := &Client{Config: &Config{UserAgent: "auto"}}
	c3.resolveUAChain()
	if len(c3.uaChain) != 3 {
		t.Fatalf("explicit auto should equal default chain, got %v", c3.uaChain)
	}

	// 零值 Client：currentUA 兜底返回主选 UA（不 panic）
	c4 := &Client{}
	if got := c4.currentUA(); got != UAAndroid2104 {
		t.Fatalf("zero-value client currentUA = %q, want %q", got, UAAndroid2104)
	}
}

// TestResetSessionClearsNegotiatedState 重置会话：AlgoID 归零 + 路由头/URLs 清空
func TestResetSessionClearsNegotiatedState(t *testing.T) {
	c := &Client{
		Config:     &Config{},
		Log:        nopLogger(),
		HttpClient: &http.Client{},
	}
	c.AlgoID = "B306E770-B7D5-49F2-A574-BCE2C5C650ED"
	c.SchoolID, c.Domain, c.Area = "3612", "kmxy.qy", "0763"
	c.IndexUrl, c.TicketUrl, c.AuthUrl = "http://a", "http://b", "http://c"
	c.Ticket, c.KeepUrl, c.TermUrl = "t", "k", "tm"
	c.cipher = NewCipher(AlgoXTea)

	c.resetSession()

	if c.AlgoID != zeroAlgoID {
		t.Fatalf("AlgoID must reset to zero uuid (docs/05 §3.2), got %q", c.AlgoID)
	}
	if c.SchoolID != "" || c.Domain != "" || c.Area != "" {
		t.Fatalf("routing headers must be cleared, got %q/%q/%q", c.SchoolID, c.Domain, c.Area)
	}
	if c.IndexUrl != "" || c.TicketUrl != "" || c.AuthUrl != "" {
		t.Fatal("portal urls must be cleared")
	}
	if c.Ticket != "" || c.KeepUrl != "" || c.TermUrl != "" {
		t.Fatal("session urls must be cleared")
	}
	if c.cipher != nil {
		t.Fatal("cipher must be cleared")
	}
	if c.ClientID == uuid.Nil {
		t.Fatal("ClientID must be regenerated")
	}
}
