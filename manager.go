package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// ManagedClient 受管理的客户端实例，包含配置和运行状态
type ManagedClient struct {
	Name          string `json:"interface"`
	Enabled       bool   `json:"enabled"`
	Status        string `json:"status"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	UserAgent     string `json:"user_agent"` // 空/auto=自动回退链；预设或自定义 UA
	CheckInterval int    `json:"check_interval"`
	RetryInterval int    `json:"retry_interval"`
	DnsAddress    string `json:"dns_address"`
	BindInterface string `json:"bind_interface"`
	MaxRetries    int    `json:"max_retries"`
	UserIP        string `json:"user_ip"`
	LastHeartbeat string `json:"last_heartbeat"`
	NextHeartbeat string `json:"next_heartbeat"`
	LastLogin     string `json:"last_login"`
	ErrorCount    int    `json:"error_count"`
	Order         int    `json:"order"`
	HasPassword   bool   `json:"has_password"` // 仅响应用：表示是否已设置密码

	client *Client
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// InterfaceView 接口对外展示视图（不含锁，避免拷贝锁警告）
type InterfaceView struct {
	Name          string `json:"interface"`
	Enabled       bool   `json:"enabled"`
	Status        string `json:"status"`
	Username      string `json:"username"`
	UserAgent     string `json:"user_agent"`
	CheckInterval int    `json:"check_interval"`
	RetryInterval int    `json:"retry_interval"`
	DnsAddress    string `json:"dns_address"`
	BindInterface string `json:"bind_interface"`
	MaxRetries    int    `json:"max_retries"`
	UserIP        string `json:"user_ip"`
	LastHeartbeat string `json:"last_heartbeat"`
	NextHeartbeat string `json:"next_heartbeat"`
	LastLogin     string `json:"last_login"`
	ErrorCount    int    `json:"error_count"`
	Order         int    `json:"order"`
	HasPassword   bool   `json:"has_password"`
}

// validInterfaceName 校验接口名是否合法，防止路径遍历。
// 允许 Unicode 字母/数字/下划线/短横线/点（含中文等），
// 禁止：空、过长、路径分隔符（/ \）、点开头（防止 .. 穿越）、控制字符、空白。
func validInterfaceName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return false
	}
	// 显式拒绝路径分隔符与空字符（filepath.Base 之外的二次保险）
	if strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return false
	}
	for _, r := range name {
		// 拒绝控制字符与所有 Unicode 空白（含普通空格、制表符等）
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
		// 拒绝 Windows 非法文件名字符，避免 session 文件写入失败
		switch r {
		case '<', '>', ':', '"', '|', '?', '*':
			return false
		}
	}
	return true
}

// validUserAgent 校验 UA 配置：空/"auto" 合法（自动链）；其他值须 ≤64 字符且不含
// 控制字符与空白——UA 会进入 HTTP 头与 XML 报文体，控制字符可造成头注入/报文损坏，
// 超长值可能被门户准入闸拒绝。
func validUserAgent(ua string) bool {
	if ua == "" || strings.EqualFold(ua, UserAgentAuto) {
		return true
	}
	if len(ua) > 64 {
		return false
	}
	for _, r := range ua {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// sanitizeName 将接口名规整为安全的文件名片段，防止路径遍历
func sanitizeName(name string) string {
	return filepath.Base(name)
}

// stopClient 安全停止客户端（统一停止路径）。
// 仅 cancel ctx 并置 nil，不等待 goroutine 退出：Start 的 defer Logout 会异步发送 term。
// term 请求携带本次认证的 ClientID/Ticket（每次认证都新生成），服务器能据此区分会话，
// 故异步发出的旧 term 不会误下线新会话。进程退出时由 Manager.wg.Wait() 等待全部 goroutine 退出。
func (mc *ManagedClient) stopClient() {
	if mc.client != nil {
		mc.client.Cancel()
		mc.client = nil
	}
}

// ManagerConfig 持久化配置结构
type ManagerConfig struct {
	Interfaces []ManagedClient `json:"interfaces"`
	Settings   Settings        `json:"settings"`
}

// Settings 全局设置
type Settings struct {
	WebPort           int    `json:"web_port"`
	DefaultMaxRetries int    `json:"default_max_retries"`
	AccessMode        string `json:"access_mode"`
	AuthCooldown      int    `json:"auth_cooldown"` // 认证冷却时间（秒），默认5，范围1-600
	LogLevel          string `json:"log_level"`    // 日志最低等级: debug, info, warn, error
}

// Manager 客户端管理器，负责配置持久化和多客户端生命周期管理
type Manager struct {
	mu         sync.RWMutex
	clients    map[string]*ManagedClient
	settings   Settings
	configPath string
	sessionsDir string
	logHub     *LogHub

	authMu       sync.Mutex   // 全局认证互斥锁
	lastAuthTime time.Time    // 上次认证完成时间

	saveMu sync.Mutex       // 串行化配置文件写入，避免并发 Save 丢更新
	wg     sync.WaitGroup   // 跟踪所有 client goroutine，用于优雅退出时等待 term 发送
}

// NewManager 创建管理器实例
func NewManager(configPath string, logHub *LogHub) *Manager {
	dir := filepath.Dir(configPath)
	return &Manager{
		clients:     make(map[string]*ManagedClient),
		settings:    Settings{WebPort: 8080, DefaultMaxRetries: 5, AuthCooldown: 5},
		configPath:  configPath,
		sessionsDir: filepath.Join(dir, "sessions"),
		logHub:      logHub,
	}
}

// getAuthCooldown 获取认证冷却时间（秒），默认5，范围1-600
func (m *Manager) getAuthCooldown() time.Duration {
	cd := m.settings.AuthCooldown
	if cd < 1 {
		cd = 5
	}
	if cd > 600 {
		cd = 600
	}
	return time.Duration(cd) * time.Second
}

// waitAuthCooldown 等待认证冷却，采用"预约占位"模式避免竞态:
// 进入时立刻把 lastAuthTime 预约到 now+wait，后续并发者基于该未来时间排队，
// 保证任意两次真实认证之间间隔不小于 cd
func (m *Manager) waitAuthCooldown(name string) {
	m.authMu.Lock()
	cd := m.getAuthCooldown()
	now := time.Now()
	next := m.lastAuthTime
	if now.After(next) {
		next = now
	}
	wait := next.Sub(now)
	// 预约本次认证的槽位
	m.lastAuthTime = next.Add(cd)
	m.authMu.Unlock()

	if wait > 0 {
		m.logHub.Add("info", fmt.Sprintf("[%s] auth cooldown, waiting %v", name, wait.Round(time.Millisecond)))
		time.Sleep(wait)
	}
}

// Load 从配置文件加载客户端列表和全局设置
func (m *Manager) Load() error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var mc ManagerConfig
	if err := json.Unmarshal(data, &mc); err != nil {
		return err
	}

	m.settings = mc.Settings
	if m.settings.WebPort == 0 {
		m.settings.WebPort = 8080
	}
	if m.settings.AuthCooldown == 0 {
		m.settings.AuthCooldown = 5
	}
	if m.settings.LogLevel == "" {
		m.settings.LogLevel = LevelInfo
	}
	m.logHub.SetLevel(m.settings.LogLevel)

	for i := range mc.Interfaces {
		iface := &mc.Interfaces[i]
		if !validInterfaceName(iface.Name) {
			return fmt.Errorf("invalid interface name at index %d: %q", i, iface.Name)
		}
		// 校验/钳制数值字段，防止手改配置导致 NewTicker 溢出 panic
		if iface.CheckInterval < 0 {
			iface.CheckInterval = 0
		}
		if iface.CheckInterval > 24*3600*1000 {
			iface.CheckInterval = 24 * 3600 * 1000
		}
		if iface.RetryInterval < -1 {
			iface.RetryInterval = -1
		}
		if iface.RetryInterval > 24*3600*1000 {
			iface.RetryInterval = 24 * 3600 * 1000
		}
		if iface.MaxRetries < 0 {
			iface.MaxRetries = 0
		}
		if iface.BindInterface != "" && !validInterfaceName(iface.BindInterface) {
			return fmt.Errorf("invalid bind_interface name at index %d: %q", i, iface.BindInterface)
		}
		// UA 非关键字段：无效值（手改配置文件）回退自动链，不阻塞加载
		if !validUserAgent(iface.UserAgent) {
			iface.UserAgent = ""
		}
		iface.Status = "disabled"
		iface.UserIP = ""
		iface.LastHeartbeat = ""
		iface.LastLogin = ""
		iface.ErrorCount = 0
		if iface.BindInterface == "" {
			iface.BindInterface = iface.Name
		}
		if iface.Order == 0 {
			iface.Order = i + 1
		}
		if _, dup := m.clients[iface.Name]; dup {
			return fmt.Errorf("duplicate interface name in config: %s", iface.Name)
		}
		m.clients[iface.Name] = iface
	}

	return nil
}

// Save 保存当前配置到文件（原子写入，避免写入中断导致配置损坏）。
// saveMu 串行化整个"读内存+写文件"过程，避免并发 Save 各自基于旧快照写入导致丢更新。
func (m *Manager) Save() error {
	m.saveMu.Lock()
	defer m.saveMu.Unlock()

	m.mu.RLock()
	mc := ManagerConfig{
		Settings: m.settings,
	}
	for _, c := range m.clients {
		c.mu.RLock()
		mc.Interfaces = append(mc.Interfaces, ManagedClient{
			Name:          c.Name,
			Enabled:       c.Enabled,
			Username:      c.Username,
			Password:      c.Password,
			UserAgent:     c.UserAgent,
			CheckInterval: c.CheckInterval,
			RetryInterval: c.RetryInterval,
			DnsAddress:    c.DnsAddress,
			BindInterface: c.BindInterface,
			MaxRetries:    c.MaxRetries,
			Order:         c.Order,
		})
		c.mu.RUnlock()
	}
	sort.Slice(mc.Interfaces, func(i, j int) bool {
		return mc.Interfaces[i].Order < mc.Interfaces[j].Order
	})
	m.mu.RUnlock()

	data, err := json.MarshalIndent(mc, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 原子写入：先写临时文件，再 rename 替换
	tmp, err := os.CreateTemp(dir, ".config-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, m.configPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// GetAll 获取全部客户端列表视图（敏感字段密码不下发，用 HasPassword 表示是否已设置）
func (m *Manager) GetAll() []InterfaceView {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]InterfaceView, 0, len(m.clients))
	for _, c := range m.clients {
		c.mu.RLock()
		v := InterfaceView{
			Name:          c.Name,
			Enabled:       c.Enabled,
			Status:        c.Status,
			Username:      c.Username,
			UserAgent:     c.UserAgent,
			CheckInterval: c.CheckInterval,
			RetryInterval: c.RetryInterval,
			DnsAddress:    c.DnsAddress,
			BindInterface: c.BindInterface,
			MaxRetries:    c.MaxRetries,
			UserIP:        c.UserIP,
			LastHeartbeat: c.LastHeartbeat,
			NextHeartbeat: c.NextHeartbeat,
			LastLogin:     c.LastLogin,
			ErrorCount:    c.ErrorCount,
			Order:         c.Order,
		}
		if c.Password != "" {
			v.HasPassword = true
		}
		c.mu.RUnlock()
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Order < result[j].Order
	})
	return result
}

// Add 添加新客户端配置
func (m *Manager) Add(mc *ManagedClient) error {
	if !validInterfaceName(mc.Name) {
		return fmt.Errorf("invalid interface name: %q", mc.Name)
	}
	if mc.BindInterface != "" && !validInterfaceName(mc.BindInterface) {
		return fmt.Errorf("invalid bind_interface name: %q", mc.BindInterface)
	}
	if mc.CheckInterval < 0 || mc.CheckInterval > 24*3600*1000 {
		return fmt.Errorf("check_interval out of range (0..%d ms)", 24*3600*1000)
	}
	if mc.RetryInterval < -1 || mc.RetryInterval > 24*3600*1000 {
		return fmt.Errorf("retry_interval out of range (-1..%d ms)", 24*3600*1000)
	}
	if !validUserAgent(mc.UserAgent) {
		return fmt.Errorf("invalid user_agent: %q (max 64 chars, no whitespace or control characters)", mc.UserAgent)
	}

	m.mu.Lock()
	if _, exists := m.clients[mc.Name]; exists {
		m.mu.Unlock()
		return fmt.Errorf("interface %s already exists", mc.Name)
	}

	mc.Status = "disabled"
	if mc.BindInterface == "" {
		mc.BindInterface = mc.Name
	}
	nextOrder := 1
	for _, c := range m.clients {
		if c.Order >= nextOrder {
			nextOrder = c.Order + 1
		}
	}
	mc.Order = nextOrder
	m.clients[mc.Name] = mc
	m.mu.Unlock()

	return m.Save()
}

// Update 更新客户端配置，运行中的客户端会自动重启
func (m *Manager) Update(name string, mc *ManagedClient) error {
	if mc.BindInterface != "" && !validInterfaceName(mc.BindInterface) {
		return fmt.Errorf("invalid bind_interface name: %q", mc.BindInterface)
	}
	if mc.CheckInterval < 0 || mc.CheckInterval > 24*3600*1000 {
		return fmt.Errorf("check_interval out of range (0..%d ms)", 24*3600*1000)
	}
	if mc.RetryInterval < -1 || mc.RetryInterval > 24*3600*1000 {
		return fmt.Errorf("retry_interval out of range (-1..%d ms)", 24*3600*1000)
	}
	if !validUserAgent(mc.UserAgent) {
		return fmt.Errorf("invalid user_agent: %q (max 64 chars, no whitespace or control characters)", mc.UserAgent)
	}

	m.mu.Lock()
	existing, exists := m.clients[name]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("interface %s not found", name)
	}

	existing.mu.Lock()
	wasRunning := existing.client != nil
	if wasRunning {
		existing.stopClient()
	}
	oldUsername, oldUserAgent := existing.Username, existing.UserAgent

	existing.Username = mc.Username
	// 密码为空时保留原密码（前端编辑时不下发密码，留空表示不改）
	if mc.Password != "" {
		existing.Password = mc.Password
	}
	existing.UserAgent = mc.UserAgent
	existing.CheckInterval = mc.CheckInterval
	existing.RetryInterval = mc.RetryInterval
	existing.DnsAddress = mc.DnsAddress
	existing.MaxRetries = mc.MaxRetries
	existing.BindInterface = mc.BindInterface
	existing.mu.Unlock()

	// UA 或账号变更后，已存会话不再匹配新配置：TryResume 会用旧 ticket 复活旧族会话
	// （心跳维持的服务器会话可存活数小时），使 UA 切换被静默搁置——删除会话强制重认证
	if oldUserAgent != mc.UserAgent || oldUsername != mc.Username {
		DeleteSession(m.sessionsDir, name)
	}
	m.mu.Unlock()

	if err := m.Save(); err != nil {
		return err
	}

	if wasRunning {
		existing.mu.RLock()
		en := existing.Enabled
		existing.mu.RUnlock()
		if en {
			return m.startClient(existing)
		}
	}
	return nil
}

// Delete 删除客户端配置并停止运行
func (m *Manager) Delete(name string) error {
	m.mu.Lock()
	mc, exists := m.clients[name]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("interface %s not found", name)
	}

	mc.mu.Lock()
	mc.stopClient()
	mc.mu.Unlock()

	delete(m.clients, name)
	m.mu.Unlock()

	return m.Save()
}

// Enable 启用客户端并开始认证
func (m *Manager) Enable(name string) error {
	m.mu.RLock()
	mc, exists := m.clients[name]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("interface %s not found", name)
	}

	mc.mu.Lock()
	if mc.Username == "" || mc.Password == "" {
		mc.mu.Unlock()
		return fmt.Errorf("username or password is empty")
	}
	mc.Enabled = true
	mc.Status = "offline"
	mc.ErrorCount = 0
	mc.mu.Unlock()

	if err := m.Save(); err != nil {
		return err
	}

	m.logHub.Add("info", fmt.Sprintf("[%s] enabled", name))
	return m.startClient(mc)
}

// Disable 禁用客户端并停止运行
func (m *Manager) Disable(name string) error {
	m.mu.RLock()
	mc, exists := m.clients[name]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("interface %s not found", name)
	}

	mc.mu.Lock()
	mc.Enabled = false
	mc.Status = "disabled"
	mc.UserIP = ""
	mc.LastHeartbeat = ""
	mc.NextHeartbeat = ""
	mc.ErrorCount = 0
	mc.stopClient()
	mc.mu.Unlock()

	if err := m.Save(); err != nil {
		return err
	}

	m.logHub.Add("info", fmt.Sprintf("[%s] disabled", name))
	return nil
}

// Login 手动触发客户端登录
func (m *Manager) Login(name string) error {
	m.mu.RLock()
	mc, exists := m.clients[name]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("interface %s not found", name)
	}

	mc.mu.RLock()
	if !mc.Enabled {
		mc.mu.RUnlock()
		return fmt.Errorf("interface %s is not enabled", name)
	}
	mc.mu.RUnlock()

	return m.startClient(mc)
}

// Logout 注销指定客户端
func (m *Manager) Logout(name string) error {
	m.mu.RLock()
	mc, exists := m.clients[name]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("interface %s not found", name)
	}

	mc.mu.Lock()
	mc.stopClient()
	mc.Status = "offline"
	mc.UserIP = ""
	mc.LastHeartbeat = ""
	mc.mu.Unlock()

	m.logHub.Add("info", fmt.Sprintf("[%s] disconnected", name))
	return nil
}

// startClient 启动客户端协程，注册状态变更、认证成功、心跳回调
func (m *Manager) startClient(mc *ManagedClient) error {
	mc.mu.Lock()
	mc.stopClient()

	cfg := &Config{
		Username:      mc.Username,
		Password:      mc.Password,
		UserAgent:     mc.UserAgent,
		CheckInterval: mc.CheckInterval,
		RetryInterval: mc.RetryInterval,
		BindInterface: mc.BindInterface,
		DnsAddress:    mc.DnsAddress,
	}

	name := mc.Name
	mc.ctx, mc.cancel = context.WithCancel(context.Background())
	// 捕获本次 ctx 到局部变量，供回调闭包判断过期。
	// 不能读 mc.ctx：startClient 重入会覆盖 mc.ctx 指向新 ctx，导致旧 goroutine
	// 的 ctxCheck 误判为"未取消"而继续写状态，污染新 client。
	ctx := mc.ctx

	client, err := NewClient(cfg, mc.ctx, mc.cancel)
	if err != nil {
		mc.cancel() // 避免 ctx 泄漏
		mc.mu.Unlock()
		return err
	}

	mc.client = client

	client.OnLog = func(level, msg string) {
		m.logHub.Add(level, fmt.Sprintf("[%s] %s", name, msg))
	}

	var lastStatus string = "offline"

	// ctxCheck 返回本次 ctx 是否已取消，用于回调中拒绝旧 goroutine 的写入
	ctxCheck := func() bool {
		select {
		case <-ctx.Done():
			return true
		default:
			return false
		}
	}

	client.OnStatusChange = func(status string) {
		if ctxCheck() {
			return
		}
		mc.mu.Lock()
		mc.Status = status
		if status == "offline" {
			mc.UserIP = ""
			mc.LastHeartbeat = ""
		}
		en := mc.Enabled
		mr := mc.MaxRetries
		mc.mu.Unlock()

		if status != lastStatus {
			m.logHub.Add("info", fmt.Sprintf("[%s] status: %s", name, status))
			lastStatus = status
		}

		if status == "offline" && en {
			mc.mu.Lock()
			mc.ErrorCount++
			ec := mc.ErrorCount
			mc.mu.Unlock()

			if mr > 0 && ec >= mr {
				mc.mu.Lock()
				mc.Enabled = false
				mc.Status = "disabled"
				mc.mu.Unlock()
				m.logHub.Add(LevelError, fmt.Sprintf("[%s] max retries %d reached, auto disabled", name, mr))
			}
		}
	}

	client.OnAuthSuccess = func(userIP string) {
		if ctxCheck() {
			return
		}
		mc.mu.Lock()
		mc.UserIP = userIP
		mc.LastLogin = time.Now().Format(time.RFC3339)
		mc.ErrorCount = 0
		mc.NextHeartbeat = ""
		mc.mu.Unlock()

		// 保存会话信息，用于意外退出后恢复；同时保存门户入口与网络配置，
		// 恢复后黑洞重认证复用 RedirectUrl、兜底 term 按原接口出报文
		if err := SaveSession(m.sessionsDir, name, &SessionData{
			ClientID:      client.ClientID.String(),
			Hostname:      client.Hostname,
			Mac:           client.MacAddress,
			UserIP:        client.UserIP,
			AcIP:          client.AcIP,
			AlgoID:        client.AlgoID,
			Ticket:        client.Ticket,
			KeepUrl:       client.KeepUrl,
			TermUrl:       client.TermUrl,
			IndexUrl:      client.IndexUrl,
			UserAgent:     client.currentUA(),
			RedirectUrl:   client.RedirectUrl,
			BindInterface: mc.BindInterface,
			DnsAddress:    mc.DnsAddress,
		}); err != nil {
			m.logHub.Add(LevelError, fmt.Sprintf("[%s] save session failed: %v", name, err))
		}

		m.logHub.Add(LevelOK, fmt.Sprintf("[%s] auth finished, ip: %s", name, userIP))
	}

	client.OnHeartbeat = func(interval int) {
		if ctxCheck() {
			return
		}
		mc.mu.Lock()
		mc.LastHeartbeat = time.Now().Format(time.RFC3339)
		mc.ErrorCount = 0
		if interval > 0 {
			mc.NextHeartbeat = time.Now().Add(time.Duration(interval) * time.Second).Format(time.RFC3339)
		}
		mc.mu.Unlock()
	}

	client.OnBeforeAuth = func() {
		m.waitAuthCooldown(name)
	}

	mc.Status = "offline"
	mc.mu.Unlock()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				m.logHub.Add(LevelError, fmt.Sprintf("[%s] panic: %v", name, r))
				mc.mu.Lock()
				mc.stopClient()
				mc.Status = "offline"
				mc.mu.Unlock()
			}
		}()

		// 尝试会话恢复：如果存在保存的会话且心跳成功，跳过认证
		if sd, err := LoadSession(m.sessionsDir, name); err == nil {
			if client.TryResume(sd) {
				m.logHub.Add(LevelOK, fmt.Sprintf("[%s] session resumed, ip: %s", name, sd.UserIP))
			} else {
				DeleteSession(m.sessionsDir, name)
				m.logHub.Add("info", fmt.Sprintf("[%s] session expired, re-auth required", name))
			}
		}

		client.Start()
	}()

	return nil
}

// GetSettings 获取全局设置
func (m *Manager) GetSettings() Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.settings
}

// UpdateSettings 更新全局设置
func (m *Manager) UpdateSettings(s Settings) error {
	if s.AuthCooldown < 1 {
		s.AuthCooldown = 1
	}
	if s.AuthCooldown > 600 {
		s.AuthCooldown = 600
	}
	if s.LogLevel == "" {
		s.LogLevel = LevelInfo
	}
	m.mu.Lock()
	m.settings = s
	m.mu.Unlock()
	m.logHub.SetLevel(s.LogLevel)
	return m.Save()
}

// StartEnabled 启动所有已启用的客户端，启动失败时自动重试等待接口就绪
func (m *Manager) StartEnabled() {
	m.mu.RLock()
	clients := make([]*ManagedClient, 0)
	for _, mc := range m.clients {
		if mc.Enabled {
			clients = append(clients, mc)
		}
	}
	m.mu.RUnlock()

	for _, mc := range clients {
		m.startClientWithRetry(mc)
	}
}

// startClientWithRetry 启动客户端并在失败时自动重试，最多等待 60 秒
func (m *Manager) startClientWithRetry(mc *ManagedClient) {
	name := mc.Name
	maxRetries := 6
	interval := 10 * time.Second

	for i := 0; i < maxRetries; i++ {
		err := m.startClient(mc)
		if err == nil {
			m.logHub.Add("info", fmt.Sprintf("[%s] auto-started", name))
			return
		}

		if i == maxRetries-1 {
			m.logHub.Add(LevelError, fmt.Sprintf("[%s] auto-start failed after %d attempts: %v", name, maxRetries, err))
			return
		}

		m.logHub.Add("info", fmt.Sprintf("[%s] auto-start failed (attempt %d/%d): %v", name, i+1, maxRetries, err))
		time.Sleep(interval)
	}
}

// StopAll 停止所有运行中的客户端
func (m *Manager) StopAll() {
	m.mu.RLock()
	clients := make([]*ManagedClient, 0, len(m.clients))
	for _, mc := range m.clients {
		clients = append(clients, mc)
	}
	m.mu.RUnlock()

	for _, mc := range clients {
		mc.mu.Lock()
		mc.stopClient()
		mc.Status = "offline"
		mc.UserIP = ""
		mc.LastHeartbeat = ""
		mc.mu.Unlock()
	}

	// 等待所有 client goroutine 退出（含 Logout defer 发送 term），最多 5 秒
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// ForceLogout 强制断开指定客户端：向服务器发送 term 请求后清除状态
func (m *Manager) ForceLogout(name string) error {
	m.mu.RLock()
	mc, exists := m.clients[name]
	m.mu.RUnlock()
	if !exists {
		return fmt.Errorf("interface %s not found", name)
	}

	// 停止运行中的 client。若已认证，Start 的 defer Logout 会发送 term；
	// 不直接读 client 字段（cipher/TermUrl 等），避免与 client goroutine 竞争。
	// 未认证或 client 未运行时，用保存的 session 兜底发 term。
	mc.mu.Lock()
	authed := mc.client != nil && mc.client.authed.Load()
	if mc.client != nil {
		mc.stopClient()
	}
	mc.mu.Unlock()

	if !authed {
		if sd, err := LoadSession(m.sessionsDir, name); err == nil {
			if m.sendTermFromSession(sd, name) {
				m.logHub.Add("info", fmt.Sprintf("[%s] force logout term sent (from session)", name))
			}
		}
	} else {
		// term 由 Start 的 defer Logout 异步发送（带旧 ClientID/Ticket，不影响后续新会话）
		m.logHub.Add("info", fmt.Sprintf("[%s] force logout, term sending in background", name))
	}

	DeleteSession(m.sessionsDir, name)

	mc.mu.Lock()
	mc.Status = "offline"
	mc.UserIP = ""
	mc.LastHeartbeat = ""
	mc.NextHeartbeat = ""
	mc.ErrorCount = 0
	mc.mu.Unlock()

	mc.mu.RLock()
	en := mc.Enabled
	mc.mu.RUnlock()
	if en {
		if err := m.Save(); err != nil {
			return err
		}
	}

	m.logHub.Add("info", fmt.Sprintf("[%s] force logout", name))
	return nil
}

// sendTermFromSession 用保存的会话构造临时 client 发送 term 请求
func (m *Manager) sendTermFromSession(sd *SessionData, name string) bool {
	clientID, err := uuid.Parse(sd.ClientID)
	if err != nil {
		return false
	}
	cipher := NewCipher(sd.AlgoID)
	if cipher == nil {
		return false
	}

	// 会话绑定了网卡时按原配置重建传输层：多 WAN 下 term 报文必须从
	// 认证时的出接口发出才能到达对应 AC；重建失败则退回默认路由（旧行为）
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if sd.BindInterface != "" && sd.BindInterface != "sys_default" {
		if tr, terr := NewHttpTransport(&Config{
			BindInterface: sd.BindInterface,
			DnsAddress:    sd.DnsAddress,
		}); terr == nil {
			httpClient.Transport = tr
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tmpClient := &Client{
		Config: &Config{},
		HttpClient: httpClient,
		Ctx:        ctx,
		Cancel:     cancel,
		ClientID:   clientID,
		Hostname:   sd.Hostname,
		MacAddress: sd.Mac,
		UserIP:     sd.UserIP,
		AcIP:       sd.AcIP,
		AlgoID:     sd.AlgoID,
		Ticket:     sd.Ticket,
		TermUrl:    sd.TermUrl,
		// 沿用登录时的 UA（报文与原会话同族；旧会话无此字段时 currentUA() 兑底默认主选）
		preferredUA: sd.UserAgent,
		cipher:     cipher,
		Log:        log.New(os.Stdout, "[force-logout:"+name+"] ", log.LstdFlags|log.Lmsgprefix),
	}
	stateXML, _ := tmpClient.GenerateStateXML()
	_, err = tmpClient.PostXMLWithTimeout(sd.TermUrl, stateXML)
	return err == nil
}
