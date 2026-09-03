// manager_session_test.go — Manager 层会话失效测试（review 发现 2）
package main

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

// TestUpdateUserAgentChangeInvalidatesSession UA/账号变更后旧会话必须删除：
// 否则 TryResume 会用旧 ticket 复活旧 UA 族会话（心跳维持的服务器会话可存活数小时），
// 使"切换认证 UA"被静默搁置到会话自然死亡。
func TestUpdateUserAgentChangeInvalidatesSession(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(filepath.Join(dir, "config.json"), nil)

	mc := &ManagedClient{Name: "wan0", Username: "u1", Password: "p", UserAgent: UAAndroid2093, BindInterface: "wan0"}
	if err := m.Add(mc); err != nil {
		t.Fatalf("add: %v", err)
	}

	saveSession := func() {
		sd := &SessionData{
			ClientID: uuid.NewString(), Hostname: "h", Mac: "02:00:00:00:00:01",
			UserIP: "10.0.0.1", AcIP: "172.16.0.1", AlgoID: AlgoXTea,
			Ticket: "tk", KeepUrl: "http://k/keep", TermUrl: "http://k/term",
			UserAgent: UAAndroid2093,
		}
		if err := SaveSession(m.sessionsDir, "wan0", sd); err != nil {
			t.Fatalf("save session: %v", err)
		}
	}

	// 基线：无关字段变更（密码/间隔）→ 会话保留（resume 是合法优化）
	saveSession()
	if err := m.Update("wan0", &ManagedClient{
		Name: "wan0", Username: "u1", Password: "p2", UserAgent: UAAndroid2093,
		CheckInterval: 10000, RetryInterval: 10000, BindInterface: "wan0",
	}); err != nil {
		t.Fatalf("update (no ua change): %v", err)
	}
	if _, err := LoadSession(m.sessionsDir, "wan0"); err != nil {
		t.Fatalf("session must survive non-UA updates: %v", err)
	}

	// UA 变更 → 会话必须删除
	if err := m.Update("wan0", &ManagedClient{
		Name: "wan0", Username: "u1", Password: "p2", UserAgent: UAPCLinux64,
		CheckInterval: 10000, RetryInterval: 10000, BindInterface: "wan0",
	}); err != nil {
		t.Fatalf("update (ua change): %v", err)
	}
	if _, err := LoadSession(m.sessionsDir, "wan0"); err == nil {
		t.Fatal("user_agent change must invalidate saved session (else TryResume revives old-family session)")
	}

	// 账号变更 → 会话同样必须删除
	saveSession()
	if err := m.Update("wan0", &ManagedClient{
		Name: "wan0", Username: "u2", Password: "p2", UserAgent: UAPCLinux64,
		CheckInterval: 10000, RetryInterval: 10000, BindInterface: "wan0",
	}); err != nil {
		t.Fatalf("update (username change): %v", err)
	}
	if _, err := LoadSession(m.sessionsDir, "wan0"); err == nil {
		t.Fatal("username change must invalidate saved session")
	}
}
