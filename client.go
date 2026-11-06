package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Client 天翼校园网认证客户端
type Client struct {
	Config                *Config
	Log                   *log.Logger
	HttpClient            *http.Client
	Ctx                   context.Context
	Cancel                context.CancelFunc
	cipher                Cipher
	heartBeatTicker       *time.Ticker
	lastHeartbeatInterval int

	UserIP     string
	AcIP       string
	Domain     string
	Area       string
	SchoolID   string
	ClientID   uuid.UUID
	Hostname   string
	MacAddress string
	Ticket     string
	AlgoID     string

	// UA 回退链（docs/08 §3）：auto 模式下按序尝试，成功值记入 preferredUA。
	// 服务端按 UA 家族分派算法池（2104→新代 9、2089→旧代 9、1003→PC 6）且按会话随机轮换。
	uaChain     []string
	uaIdx       int
	preferredUA string

	IndexUrl    string
	TicketUrl   string
	AuthUrl     string
	KeepUrl     string
	TermUrl     string
	RedirectUrl string

	OnStatusChange func(status string)
	OnAuthSuccess  func(userIP string)
	OnHeartbeat    func(interval int)
	OnBeforeAuth   func()
	OnLog          func(level, msg string)
	LogEnabled     func(level string) bool // nil keeps the unfiltered client logger behavior

	authed       atomic.Bool // 认证成功后置位；Logout 据此决定是否发送 term
	lastAuthFail time.Time

	// consecutiveCheckFailures 连续网络检查异常计数（请求失败或非 204/302 状态码）。
	// 达到 blackholeReauthThreshold 后主动发起重认证，突破“只有 302 才重新认证”
	// 的单一恢复路径：多 WAN 负载均衡下报文选路不对称、上游 uRPF 丢弃等场景
	// 会造成黑洞（无响应、无重定向），旧逻辑此时会永久卡死。
	consecutiveCheckFailures int

	// consecutiveHeartbeatFails 连续心跳失败计数（独立于检查计数：
	// “门户不可达但外网正常”的退化期，心跳失败后的 recheck 会成功，
	// 若共用计数器会被成功 recheck 清零，心跳阈值永远无法触发——
	// 实测事故中三次心跳失败均停在 (1 consecutive) 即此缺陷）。
	// 仅由成功的心跳清零。
	consecutiveHeartbeatFails int

	// consecutiveAuthFails 连续认证失败次数，驱动指数退避（authBackoff）。
	// 成功认证时清零；确认在线（204/IP 探针可达未劫持）不清零：
	// 会话状态丢失时的重认领节奏由退避控制，若被在线态清零会退化为
	// 每 tick 一次的高频重认证风暴（实测事故后审发现的缺陷）。
	consecutiveAuthFails int

	// heartbeatPaused 心跳当前是否处于暂停态（ticker 停在 MaxInt64）。
	// 暂停发生在 302 检测与心跳失败强制重认证两处；恢复点：Login 成功、
	// 心跳成功、以及 204 恢复后对完好会话的重启（recoverAfterOnline）。
	heartbeatPaused bool
}

func (c *Client) logf(level, format string, v ...interface{}) {
	if c.LogEnabled != nil && !c.LogEnabled(level) {
		return
	}
	msg := fmt.Sprintf(format, v...)
	c.Log.Printf("[%s] %s", level, msg)
	if c.OnLog != nil {
		c.OnLog(level, msg)
	}
}

func (c *Client) logln(level, msg string) {
	if c.LogEnabled != nil && !c.LogEnabled(level) {
		return
	}
	c.Log.Println("[" + level + "] " + msg)
	if c.OnLog != nil {
		c.OnLog(level, msg)
	}
}

// RetryIntervalNever 表示不自动重试认证（约定值，任意负数等效）
const RetryIntervalNever = -1

// zeroAlgoID ZSM 握手的初始算法 ID（首次握手 body；每次认证尝试必须重新归零，
// 带上次 GUID 再握会被拒 Error-Code 1，docs/05 §3.2）
const zeroAlgoID = "00000000-0000-0000-0000-000000000000"

// blackholeReauthThreshold 连续网络检查异常达到此次数后触发主动重认证。
// 取 3：默认 10s 检查间隔下约 30s 判定网络黑洞，远小于会话超时，误判代价低。
const blackholeReauthThreshold = 3

// maxAuthBackoffShift 连续认证失败指数退避的最大倍移：退避上限为 retry_interval 的 16 倍。
// 长时间黑洞下高频认证请求可能触发校园网风控加重处罚，指数退避降低请求频率。
const maxAuthBackoffShift = 4

// defaultHeartbeatInterval 服务端未下发心跳间隔时的兜底值（秒），与 Login 响应
// keep-retry 缺失时的兜底一致。
const defaultHeartbeatInterval = 60

// checkURL 主探测 URL（域名形态，依赖 DNS）：204=在线，302=未认证。
const checkURL = "http://connect.rom.miui.com/generate_204"

// fallbackProbeTimeout 单次 IP 直连探测的超时。探测在检查循环内串行执行，
// 过长会拖慢黑洞判定，过短易误判丢包，取 4 秒。
const fallbackProbeTimeout = 4 * time.Second

// fallbackProbeURLs DNS 无关的公共探针（IP 直连，无域名解析），按序尝试：
//  1. CheckNetwork 回退探测：校园网认证失效时 DNS 通常被一并切断，域名探测必然
//     超时；IP 直连可区分「会话失效（被 BRAS 劫持 302）」「仅 DNS 受损（有响应）」
//     「真黑洞（全部超时）」三种状态，避免把可恢复状态误判成黑洞反复重认证；
//  2. discoverRedirectEntry：探针被劫持时 302 的 Location 即门户入口。
//
// 候选为国内公共 DNS 的 HTTP 端点（实测稳定响应 404，延迟 <50ms）。
var fallbackProbeURLs = []string{
	"http://223.5.5.5/",
	"http://119.29.29.29/",
}

// NewClient 创建认证客户端，使用外部提供的 ctx/cancel
func NewClient(config *Config, ctx context.Context, cancel context.CancelFunc) (*Client, error) {
	if config.Username == "" || config.Password == "" {
		return nil, errors.New("username or password is empty")
	}

	transport, err := NewHttpTransport(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}

	// 门户可能通过 Set-Cookie 维持会话上下文，协议分析建议保留 CookieJar
	jar, _ := cookiejar.New(nil)

	rid := GenerateRandomString(5)

	if config.BindInterface == "" {
		config.BindInterface = "sys_default"
	}
	if config.CheckInterval <= 0 {
		config.CheckInterval = 10000
	}
	if config.RetryInterval < 0 {
		// 负值（约定为 RetryIntervalNever）表示不重试：用 MaxInt32 ms（≈24 天）
		// 实际禁用重试，且不会让 time.Duration 乘法溢出
		config.RetryInterval = math.MaxInt32
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = 10000
	}

	cl := &Client{
		Config: config,
		Ctx:    ctx,
		Cancel: cancel,
		HttpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: transport,
			Jar:       jar,
		},
		AlgoID: zeroAlgoID,
		Log: log.New(
			os.Stdout,
			"["+rid+"][user:"+config.Username+" bind_device:"+config.BindInterface+"] ",
			log.LstdFlags|log.Lmsgprefix,
		),
		heartBeatTicker: time.NewTicker(time.Duration(math.MaxInt64)),
		heartbeatPaused: true,
	}
	cl.resolveUAChain()

	return cl, nil
}

// currentUA 返回当前生效的 User-Agent：HTTP 头与 XML <user-agent> 报文体必须同源于此。
// 优先上次成功值（preferredUA），其次回退链当前游标；零值 Client 兑底返回主选 UA。
func (c *Client) currentUA() string {
	if c.preferredUA != "" {
		return c.preferredUA
	}
	if c.uaIdx >= 0 && c.uaIdx < len(c.uaChain) {
		return c.uaChain[c.uaIdx]
	}
	return UAAndroid2104
}

// resolveUAChain 把配置解析为回退链（docs/08 §3.2）：
//   - 空/"auto"（缺省）→ 默认链 [2104→2089→2093]，上次成功值置链首以跳过已知会失败的尝试；
//   - 其他任意值（预设或手输）→ 单元素链，不做回退。
func (c *Client) resolveUAChain() {
	configured := strings.TrimSpace(c.Config.UserAgent)
	auto := configured == "" || strings.EqualFold(configured, UserAgentAuto)
	if !auto && !validUserAgent(configured) {
		// 与 manager 层校验保持一致：非法配置值（含带空白的 " auto " 等边界）回退自动链，
		// 防御直接构造 Config 的路径（Add/Update 在入口层已拒绝非法值）
		auto = true
	}

	var chain []string
	if auto {
		chain = append(chain, defaultUAChain...)
		if c.preferredUA != "" {
			rest := make([]string, 0, len(chain))
			for _, ua := range chain {
				if ua != c.preferredUA {
					rest = append(rest, ua)
				}
			}
			chain = append([]string{c.preferredUA}, rest...)
		}
	} else {
		chain = []string{configured}
	}
	c.uaChain = chain
	c.uaIdx = 0
}

// resetSession 为一次认证尝试重置会话（uaprobe 方法论：每轮独立会话）。
// ⚠️ AlgoID 必须归零：GetAlgoId 的 body=当前 AlgoID，成功认证后重认证若带着上次
// GUID 再握会被拒（Error-Code 1，docs/05 §3.2）——旧代码在重认证路径上存在此隐患。
func (c *Client) resetSession() {
	c.ClientID = uuid.New()
	c.Hostname = GenerateRandomString(10)
	c.MacAddress = GenerateRandomMAC()
	c.AlgoID = zeroAlgoID
	c.SchoolID, c.Domain, c.Area = "", "", ""
	c.IndexUrl, c.TicketUrl, c.AuthUrl = "", "", ""
	c.Ticket, c.KeepUrl, c.TermUrl = "", "", ""
	c.cipher = nil
	// 独立 CookieJar：门户通过 Set-Cookie 维持会话上下文，跨尝试不得复用
	if jar, err := cookiejar.New(nil); err == nil {
		c.HttpClient.Jar = jar
	}
}

// pauseHeartbeat 暂停心跳：进入认证链/强制重认证前调用，避免旧会话心跳与
// 认证请求交叠。恢复点见 resumeHeartbeat。
func (c *Client) pauseHeartbeat() {
	c.heartBeatTicker.Reset(time.Duration(math.MaxInt64))
	c.heartbeatPaused = true
}

// resumeHeartbeat 恢复心跳：优先使用服务端最近一次下发的间隔，缺失时兜底。
func (c *Client) resumeHeartbeat() {
	interval := c.lastHeartbeatInterval
	if interval <= 0 {
		interval = defaultHeartbeatInterval
	}
	c.heartBeatTicker.Reset(time.Duration(interval) * time.Second)
	c.heartbeatPaused = false
}

// authBackoff 当前状态下的认证重试退避间隔：以 retry_interval 为基，连续失败
// 每次翻倍，封顶 16 倍。长时间黑洞下高频认证可能触发校园网风控加重处罚。
// RetryInterval <= 0（RetryIntervalNever 已在 NewClient 归一为极大值）不会走到 0 分支，
// 此处对 0/负值返回 0 表示不退避，由调用方决定语义。
func (c *Client) authBackoff() time.Duration {
	base := time.Duration(c.Config.RetryInterval) * time.Millisecond
	if base <= 0 {
		return 0
	}
	shift := c.consecutiveAuthFails - 1
	if shift < 0 {
		shift = 0
	}
	if shift > maxAuthBackoffShift {
		shift = maxAuthBackoffShift
	}
	return base << uint(shift)
}

// Start 启动客户端主循环，定期检测网络状态并发送心跳
func (c *Client) Start() {
	c.logln("info", "client start")
	defer c.HttpClient.CloseIdleConnections()
	defer c.heartBeatTicker.Stop()
	defer c.Logout()

	if err := c.CheckNetwork(); err != nil {
		c.logf("warn", "network check failed: %v", err)
		if c.OnStatusChange != nil {
			c.OnStatusChange("degraded")
		}
		// 首次探测失败同样计入黑洞判定：enable-during-blackhole 场景下
		// 不应白白丢弃这一次失败信号，否则阈值判定被推迟一个检查周期
		c.consecutiveCheckFailures++
	}

	ticker := time.NewTicker(time.Millisecond * time.Duration(c.Config.CheckInterval))
	defer ticker.Stop()

	for {
		select {
		case <-c.Ctx.Done():
			c.logln("info", "client context cancel")
			return
		case <-ticker.C:
			if !c.lastAuthFail.IsZero() && c.Config.RetryInterval > 0 {
				remain := c.authBackoff() - time.Since(c.lastAuthFail)
				if remain > 0 {
					c.logf("debug", "retry cooldown, waiting %v", remain)
					continue
				}
			}
			checkErr := c.CheckNetwork()
			if checkErr != nil {
				if c.OnStatusChange != nil {
					c.OnStatusChange("degraded")
				}
				c.consecutiveCheckFailures++
				c.logf("warn", "network check failed (%d consecutive): %v", c.consecutiveCheckFailures, checkErr)
				// 黑洞自愈：连续多次探测异常（超时/DNS失败/非204状态码）时，
				// 会话很可能已死且拿不到 302 重定向，主动重新认证。
				if c.consecutiveCheckFailures >= blackholeReauthThreshold {
					c.logln("warn", "network unreachable repeatedly, forcing re-auth")
					c.consecutiveCheckFailures = 0
					c.HandleRedirect(nil)
				}
			} else {
				c.consecutiveCheckFailures = 0
			}
		case <-c.heartBeatTicker.C:
			err := c.SendHeartbeat()
			if err != nil {
				c.onHeartbeatError(err)
			} else {
				c.consecutiveCheckFailures = 0
				c.consecutiveHeartbeatFails = 0
				c.logln("debug", "send heartbeat")
				if c.OnStatusChange != nil {
					c.OnStatusChange("online")
				}
				if c.OnHeartbeat != nil {
					c.OnHeartbeat(c.lastHeartbeatInterval)
				}
			}
		}
	}
}

// onHeartbeatError 心跳失败处理：独立计数（consecutiveHeartbeatFails），达到
// 阈值时停发心跳并强制重认证；未达阈值时同步做一次网络检查（仅作诊断日志，
// 其成功不得清零心跳计数——否则“门户退化但外网正常”期间阈值永不到达）。
func (c *Client) onHeartbeatError(err error) {
	c.logf("warn", "send heartbeat error: %v", err)
	c.consecutiveHeartbeatFails++
	c.logf("warn", "heartbeat failed (%d consecutive)", c.consecutiveHeartbeatFails)
	if c.consecutiveHeartbeatFails >= blackholeReauthThreshold {
		c.logln("warn", "heartbeat failed repeatedly, forcing re-auth")
		c.consecutiveHeartbeatFails = 0
		c.pauseHeartbeat()
		c.HandleRedirect(nil)
	} else if cerr := c.CheckNetwork(); cerr != nil {
		c.logf("warn", "network recheck failed: %v", cerr)
	}
}

// SendHeartbeat 发送心跳包，维持在线状态
func (c *Client) SendHeartbeat() error {
	stateXML, err := c.GenerateStateXML()
	if err != nil {
		return err
	}

	decrypted, err := c.PostXML(c.KeepUrl, stateXML)
	if err != nil {
		return err
	}

	var stateResp StateResponse
	if err = xml.Unmarshal(decrypted, &stateResp); err != nil {
		return err
	}

	interval, parseErr := strconv.Atoi(stateResp.Interval)
	if parseErr != nil || interval <= 0 {
		// interval 是服务端可选下发的字段：缺失或非法时保持现有间隔，
		// 心跳本身已成功送达，不应计入连续失败（否则会造成误判掉线）
		c.logf("debug", "heartbeat interval not updated (%q)", stateResp.Interval)
		return nil
	}

	c.lastHeartbeatInterval = interval
	c.resumeHeartbeat()
	return nil
}

// Logout 在客户端停止时向服务器发送下线请求，清理服务器侧会话。
// 由 Start 的 defer 调用；此时 ctx 通常已取消，故使用带独立超时的 PostXMLWithTimeout
// （它内部创建临时 context，不受 c.Ctx 取消影响）。
// 仅在本次曾认证成功（authed）时发送，避免对未认证 client 发无意义请求。
func (c *Client) Logout() {
	if !c.authed.Load() {
		return
	}
	if c.cipher == nil || c.TermUrl == "" {
		return
	}
	stateXML, err := c.GenerateStateXML()
	if err != nil {
		c.logf("warn", "logout: build state xml failed: %v", err)
		return
	}
	if _, err := c.PostXMLWithTimeout(c.TermUrl, stateXML); err != nil {
		c.logf("warn", "logout: send term failed: %v", err)
		return
	}
	c.logln("info", "log out request sent")
}

// probeGet 单次 DNS 无关 GET 探测（独立短超时，不占用 c.Ctx 的生命周期控制）。
func (c *Client) probeGet(ctx context.Context, url string) (*http.Response, error) {
	request, err := c.NewGetRequestWithCustomCtx(ctx, url)
	if err != nil {
		return nil, err
	}
	return c.HttpClient.Do(request)
}

// probeWithoutDNS IP 直连探测：域名解析失败后判定真实网络状态。
// 返回首个可达探针的响应；全部不可达时返回聚合错误（便于一次看全诊断信息）。
func (c *Client) probeWithoutDNS() (*http.Response, error) {
	var probeErrs []string
	for _, u := range fallbackProbeURLs {
		ctx, cancel := context.WithTimeout(c.Ctx, fallbackProbeTimeout)
		resp, err := c.probeGet(ctx, u)
		cancel()
		if err == nil {
			c.logf("debug", "dns-free probe %s reachable (http %d)", u, resp.StatusCode)
			return resp, nil
		}
		probeErrs = append(probeErrs, fmt.Sprintf("%s: %v", u, err))
	}
	return nil, errors.New(strings.Join(probeErrs, "; "))
}

// CheckNetwork 检测网络状态，未认证时自动触发认证流程。
// 域名探测因 DNS 解析失败而失败时（校园网认证失效的典型伴生症状，黑洞期
// DNS 与普通流量一同被切），回退 IP 直连探测细分三种状态：
//   - 302（被 BRAS 劫持）→ 未认证，进入认证链；
//   - 其他 HTTP 响应（404/200 等）→ 网络路径可达、仅 DNS 受损 → 视为在线，
//     不计失败（否则纯 DNS 抖动会触发无意义的重认证循环）；
//   - 全部超时/失败 → 真黑洞，返回错误交由调用方计数。
func (c *Client) CheckNetwork() error {
	request, err := c.NewGetRequest(checkURL)
	if err != nil {
		return err
	}

	resp, err := c.HttpClient.Do(request)
	viaFallback := false
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) {
			return err
		}
		// DNS 解析失败：降级为 DNS 无关探测，避免把“仅 DNS 受损”误判为黑洞
		resp, err = c.probeWithoutDNS()
		if err != nil {
			return fmt.Errorf("dns check failed: %v; dns-free probes also failed: %w", dnsErr, err)
		}
		viaFallback = true
	}
	if resp == nil {
		return errors.New("nil response")
	}
	defer func(Body io.ReadCloser) {
		if Body != nil {
			_ = Body.Close()
		}
	}(resp.Body)

	switch {
	case resp.StatusCode == http.StatusNoContent:
		c.consecutiveCheckFailures = 0
		// 注意：此处不清认证失败退避状态（lastAuthFail/consecutiveAuthFails）。
		// 会话丢失时的重认领节奏由退避控制；若被在线态清零，退避失效。
		c.recoverAfterOnline()
		if c.OnStatusChange != nil {
			c.OnStatusChange("online")
		}
		return nil

	case resp.StatusCode == http.StatusFound || (viaFallback && isRedirectStatus(resp.StatusCode)):
		c.consecutiveCheckFailures = 0
		// 探测重定向响应本身也可能携带路由头，先采集再进入认证链
		c.harvestCDC(resp)
		c.pauseHeartbeat()
		c.logln("info", "auth required")
		if c.OnStatusChange != nil {
			c.OnStatusChange("auth")
		}
		return c.HandleRedirect(resp)

	case viaFallback:
		// IP 探针可达但未被劫持：仅 DNS 受损，视为在线（同样不清认证退避状态）
		c.consecutiveCheckFailures = 0
		c.recoverAfterOnline()
		if c.OnStatusChange != nil {
			c.OnStatusChange("online")
		}
		return nil

	default:
		// 非 204/302（如 200 弹窗页、502 网关错误）：视为异常，交给调用方计数
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}

// recoverAfterOnline 会话状态自愈：网络恢复但本 client 不持有有效会话时主动重建，
// 消除“在线但无人保活”的僵户窗口——BRAS 侧旧会话可能仍有效，但本 client 的
// 会话字段已被失败的强制重认证清空（resetSession），既发不出心跳也无法感知
// 服务端后续踢会话；放任不管则最长数小时后服务端超时才会以 302 触发重认证。
func (c *Client) recoverAfterOnline() {
	if !c.authed.Load() {
		return // 从未认证过：仅监控，等首次 302 触发认证
	}
	if c.KeepUrl != "" {
		// 会话字段完好但心跳被暂停（如认证链中途失败后网络自行恢复）：重启心跳
		if c.heartbeatPaused {
			c.resumeHeartbeat()
		}
		return
	}
	c.logln("warn", "online but session state lost, re-adopting session")
	_ = c.HandleRedirect(nil)
}

// HandleRedirect 处理 302 重定向，执行认证。
// resp 为 nil 时表示“强制重认证”（网络黑洞自愈路径）：不经过重定向探测，
// 直接从零开始完整认证流程，由服务器报错（missing school info 等）兜底。
func (c *Client) HandleRedirect(resp *http.Response) error {
	if c.OnBeforeAuth != nil {
		c.OnBeforeAuth()
	}
	var redirectURL string
	if resp != nil {
		redirectURL = resp.Header.Get("Location")
	}
	if err := c.Auth(redirectURL); err != nil {
		c.logf("warn", "auth failed: %v", err)
		c.lastAuthFail = time.Now()
		c.consecutiveAuthFails++
		if c.OnStatusChange != nil {
			c.OnStatusChange("offline")
		}
		return nil
	}

	c.lastAuthFail = time.Time{}
	c.consecutiveAuthFails = 0
	c.logln("ok", "auth finished")
	if c.OnStatusChange != nil {
		c.OnStatusChange("online")
	}
	if c.OnAuthSuccess != nil {
		c.OnAuthSuccess(c.UserIP)
	}
	return nil
}

// TryResume 尝试用保存的会话恢复心跳连接，成功返回 true
func (c *Client) TryResume(sd *SessionData) bool {
	// 恢复会话字段
	clientID, err := uuid.Parse(sd.ClientID)
	if err != nil {
		c.logf("warn", "resume: invalid client id: %v", err)
		return false
	}
	c.ClientID = clientID
	c.Hostname = sd.Hostname
	c.MacAddress = sd.Mac
	c.UserIP = sd.UserIP
	c.AcIP = sd.AcIP
	c.AlgoID = sd.AlgoID
	c.Ticket = sd.Ticket
	c.KeepUrl = sd.KeepUrl
	c.TermUrl = sd.TermUrl
	c.IndexUrl = sd.IndexUrl
	// 恢复登录时的 UA（心跳/下线报文与原会话同族），并置为后续强制重认证的首选
	c.preferredUA = sd.UserAgent
	// 恢复门户入口地址：进程重启后黑洞自愈的强制重认证需要复用它
	c.RedirectUrl = sd.RedirectUrl

	// 重建加密器
	c.cipher = NewCipher(c.AlgoID)
	if c.cipher == nil {
		c.logf("warn", "resume: unknown algo id: %s", c.AlgoID)
		return false
	}

	// 尝试发送心跳
	if err := c.SendHeartbeat(); err != nil {
		c.logf("warn", "resume: heartbeat failed: %v", err)
		return false
	}

	c.authed.Store(true)
	c.logln("ok", "session resumed successfully")
	if c.OnStatusChange != nil {
		c.OnStatusChange("online")
	}
	if c.OnAuthSuccess != nil {
		c.OnAuthSuccess(c.UserIP)
	}
	if c.OnHeartbeat != nil {
		c.OnHeartbeat(c.lastHeartbeatInterval)
	}
	return true
}
