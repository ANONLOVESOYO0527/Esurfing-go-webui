package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SessionData 持久化的认证会话信息，用于意外退出后恢复心跳
type SessionData struct {
	ClientID string `json:"client_id"`
	Hostname string `json:"hostname"`
	Mac      string `json:"mac"`
	UserIP   string `json:"user_ip"`
	AcIP     string `json:"ac_ip"`
	AlgoID   string `json:"algo_id"`
	Ticket   string `json:"ticket"`
	KeepUrl  string `json:"keep_url"`
	TermUrl  string `json:"term_url"`
	IndexUrl string `json:"index_url"`

	// RedirectUrl 门户入口地址：恢复会话后若遇黑洞需强制重认证，
	// 复用它可脱离 DNS（门户地址通常为 IP 直连）
	RedirectUrl string `json:"redirect_url,omitempty"`

	// BindInterface/DnsAddress 认证时的网络配置：
	// 兜底发送 term 需按原认证路径绑定出接口（多 WAN 场景）
	BindInterface string `json:"bind_interface,omitempty"`
	DnsAddress    string `json:"dns_address,omitempty"`

	SavedAt string `json:"saved_at"`
}

// sessionPath 返回会话文件路径，name 经 filepath.Base 规整防止路径遍历
func sessionPath(sessionsDir, name string) string {
	return filepath.Join(sessionsDir, filepath.Base(name)+".json")
}

// SaveSession 保存会话信息到文件（权限 0600，仅属主可读写）
func SaveSession(sessionsDir, name string, sd *SessionData) error {
	if err := os.MkdirAll(sessionsDir, 0755); err != nil {
		return fmt.Errorf("create sessions dir: %w", err)
	}
	sd.SavedAt = time.Now().Format(time.RFC3339)
	data, err := json.MarshalIndent(sd, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	path := sessionPath(sessionsDir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	// 显式收紧已有文件权限（WriteFile 对已存在文件不改权限）
	_ = os.Chmod(path, 0600)
	return nil
}

// LoadSession 从文件加载会话信息
func LoadSession(sessionsDir, name string) (*SessionData, error) {
	data, err := os.ReadFile(sessionPath(sessionsDir, name))
	if err != nil {
		return nil, err
	}
	var sd SessionData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, err
	}
	if sd.ClientID == "" || sd.Ticket == "" || sd.KeepUrl == "" {
		return nil, fmt.Errorf("incomplete session data")
	}
	return &sd, nil
}

// DeleteSession 删除会话文件
func DeleteSession(sessionsDir, name string) {
	_ = os.Remove(sessionPath(sessionsDir, name))
}
