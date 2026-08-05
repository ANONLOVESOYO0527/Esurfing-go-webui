package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Client 天翼校园网认证客户端
type Client struct {
	Config          *Config
	Log             *log.Logger
	HttpClient      *http.Client
	Ctx             context.Context
	Cancel          context.CancelFunc
	cipher          Cipher
	heartBeatTicker *time.Ticker
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

	authed       atomic.Bool // 认证成功后置位；Logout 据此决定是否发送 term
	lastAuthFail time.Time
}

func (c *Client) logf(level, format string, v ...interface{}) {
	c.Log.Printf("["+level+"] "+format, v...)
	if c.OnLog != nil {
		c.OnLog(level, fmt.Sprintf(format, v...))
	}
}

func (c *Client) logln(level, msg string) {
	c.Log.Println("[" + level + "] " + msg)
	if c.OnLog != nil {
		c.OnLog(level, msg)
	}
}

// RetryIntervalNever 表示不自动重试认证（约定值，任意负数等效）
const RetryIntervalNever = -1

// NewClient 创建认证客户端，使用外部提供的 ctx/cancel
func NewClient(config *Config, ctx context.Context, cancel context.CancelFunc) (*Client, error) {
	if config.Username == "" || config.Password == "" {
		return nil, errors.New("username or password is empty")
	}

	transport, err := NewHttpTransport(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport: %w", err)
	}

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
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: transport,
		},
		AlgoID: "00000000-0000-0000-0000-000000000000",
		Log: log.New(
			os.Stdout,
			"["+rid+"][user:"+config.Username+" bind_device:"+config.BindInterface+"] ",
			log.LstdFlags|log.Lmsgprefix,
		),
		heartBeatTicker: time.NewTicker(time.Duration(math.MaxInt64)),
	}

	return cl, nil
}

// Start 启动客户端主循环，定期检测网络状态并发送心跳
func (c *Client) Start() {
	c.logln("info", "client start")
	defer c.heartBeatTicker.Stop()
	defer c.Logout()

	if err := c.CheckNetwork(); err != nil {
		c.logf("warn", "network check failed: %v", err)
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
				remain := time.Duration(c.Config.RetryInterval)*time.Millisecond - time.Since(c.lastAuthFail)
				if remain > 0 {
					c.logf("debug", "retry cooldown, waiting %v", remain)
					continue
				}
			}
			if err := c.CheckNetwork(); err != nil {
				c.logf("warn", "network check failed: %v", err)
			}
		case <-c.heartBeatTicker.C:
			err := c.SendHeartbeat()
			if err != nil {
				c.logf("warn", "send heartbeat error: %v", err)
				if err := c.CheckNetwork(); err != nil {
					c.logf("warn", "network recheck failed: %v", err)
				}
			} else {
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

	interval, err := strconv.Atoi(stateResp.Interval)
	if err != nil {
		return err
	}

	c.heartBeatTicker.Reset(time.Duration(interval) * time.Second)
	c.lastHeartbeatInterval = interval
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

// CheckNetwork 检测网络状态，未认证时自动触发认证流程
func (c *Client) CheckNetwork() error {
	request, err := c.NewGetRequest("http://connect.rom.miui.com/generate_204")
	if err != nil {
		return err
	}

	resp, err := c.HttpClient.Do(request)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("nil response")
	}
	defer func(Body io.ReadCloser) {
		if Body != nil {
			_ = Body.Close()
		}
	}(resp.Body)

	switch resp.StatusCode {
	case http.StatusNoContent:
		if c.OnStatusChange != nil {
			c.OnStatusChange("online")
		}
		return nil

	case http.StatusFound:
		c.heartBeatTicker.Reset(time.Duration(math.MaxInt64))
		c.logln("info", "auth required")
		if c.OnStatusChange != nil {
			c.OnStatusChange("auth")
		}
		return c.HandleRedirect(resp)

	default:
		return errors.New(fmt.Sprintf("unexpected status code: %d", resp.StatusCode))
	}
}

// HandleRedirect 处理 302 重定向，执行认证
func (c *Client) HandleRedirect(resp *http.Response) error {
	if c.OnBeforeAuth != nil {
		c.OnBeforeAuth()
	}
	if err := c.Auth(resp.Header.Get("Location")); err != nil {
		c.logf("warn", "auth failed: %v", err)
		c.lastAuthFail = time.Now()
		if c.OnStatusChange != nil {
			c.OnStatusChange("offline")
		}
		return nil
	}

	c.lastAuthFail = time.Time{}
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
