package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// GetInterfaceIP 获取指定网络接口的 IPv4 地址
func GetInterfaceIP(interfaceName string) (string, error) {
	iFace, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("interface not found: %v", err)
	}

	if iFace.Flags&net.FlagUp == 0 {
		return "", fmt.Errorf("interface %s is down", interfaceName)
	}

	addresses, err := iFace.Addrs()
	if err != nil {
		return "", fmt.Errorf("can not get addresses from interface %s: %v", interfaceName, err)
	}

	for _, addr := range addresses {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}

		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}

		ipv4 := ip.To4()
		if ipv4 == nil {
			continue
		}

		return ipv4.String(), nil
	}

	return "", fmt.Errorf("no available ipv4 address at interface %s", interfaceName)
}

// maxCDCHeaderValueLen 单个路由头存储上限：防止异常/恶意大响应撑爆内存，
// 也避免把超长值回传到后续请求头导致上游拒绝
const maxCDCHeaderValueLen = 128

// clampCDCValue 规整路由头值：去空白、限长。
func clampCDCValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > maxCDCHeaderValueLen {
		return v[:maxCDCHeaderValueLen]
	}
	return v
}

// sanitizeSnippet 将远端返回的字节片段安全化为可打印文本（用于日志与错误信息）：
// 先截断再替换非法 UTF-8 与控制字符，防止终端转义注入与日志伪造；
// 保留换行/制表符便于阅读 XML 报文类内容。
func sanitizeSnippet(data []byte, max int) string {
	if len(data) > max {
		data = data[:max]
	}
	s := strings.ToValidUTF8(string(data), "?")
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			b.WriteByte('.')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// extractJSRedirect 从 HTML 中提取 JavaScript 页面跳转地址（location.href 等），
// 返回原始（可能相对的）跳转串；未命中返回空字符串。
func extractJSRedirect(content string) string {
	for _, pat := range []string{
		`location.href="`, `location.replace("`, `window.location="`, `window.location.href="`,
	} {
		if i := strings.Index(content, pat); i >= 0 {
			start := i + len(pat)
			if end := strings.Index(content[start:], `"`); end > 0 {
				return content[start : start+end]
			}
		}
	}
	return ""
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GenerateRandomString 生成指定长度的随机字符串
func GenerateRandomString(length int) string {
	if length <= 0 {
		return ""
	}

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.N(len(charset))]
	}
	return string(b)
}

// GenerateRandomMAC 生成随机本地管理MAC地址
func GenerateRandomMAC() string {
	mac := make([]byte, 6)

	for i := range mac {
		mac[i] = byte(rand.N(256))
	}

	mac[0] = (mac[0] & 0xfe) | 0x02

	return net.HardwareAddr(mac).String()
}

// DecodeAlgoID 解析 ZSM 握手响应，返回算法 ID 与密钥材料。
// 官方客户端逆向确认的二进制格式：
//
//	[4 字节头，其中 byte[3]=keyLen] [keyLen 字节 key] [1 字节分隔符 '$'] [36 字节 UUID = Algo-ID] ...
//
// key 仅作透传（真正加解密用本地固定密钥表）；若把分隔符字节当长度读会碰巧工作
//（'$'=0x24=36 恰好等于 UUID 长度），但语义错误，此处按官方格式固定读取。
func DecodeAlgoID(data []byte) (algoID string, key string, err error) {
	dataLen := len(data)
	if dataLen < 4 {
		return "", "", errors.New("data Error: insufficient header length")
	}

	len1 := int(data[3])
	pos := 4

	if pos+len1 > dataLen {
		return "", "", errors.New("data Error: key length exceeds data size")
	}
	keyBytes := data[pos : pos+len1]
	pos += len1

	// 跳过 1 字节分隔符（官方为 '$'）
	if pos >= dataLen {
		return "", "", errors.New("data Error: missing algoID separator")
	}
	pos++

	const algoIDLen = 36 // 标准格式下 Algo-ID 是定长 36 字节的 UUID 字符串
	if pos+algoIDLen > dataLen {
		return "", "", errors.New("data Error: algoID length exceeds data size")
	}
	algoIDBytes := data[pos : pos+algoIDLen]

	return string(algoIDBytes), string(keyBytes), nil
}

// ConfigStartTag 门户配置块起始标记（无尾随空格：真实页面中后面跟随换行或属性文本，
// 匹配时不应依赖分隔符的具体形态）
const ConfigStartTag = "<!--//config.campus.js.chinatelecom.com"
const ConfigEndTag = "//config.campus.js.chinatelecom.com-->"

// FormatEConfig 从HTML中提取并格式化服务器配置XML。
// 用前缀定位而非 Split 精确匹配：兼容起始标记后接空格、换行或属性文本等多种页面形态；
// 起始标记到结束标记之间的残余内容可能包含属性文本（如 "width=720"），
// 配置块真正的起点是其后第一个 '<'。
func FormatEConfig(data []byte) ([]byte, error) {
	s := string(data)

	startLen := len(ConfigStartTag)
	idx := strings.Index(s, ConfigStartTag)
	if idx < 0 {
		return nil, errors.New("config start tag not found in response")
	}
	rest := s[idx+startLen:]

	endIdx := strings.Index(rest, ConfigEndTag)
	if endIdx < 0 {
		return nil, errors.New("config end tag not found in response")
	}
	rest = rest[:endIdx]

	// 跳到配置块第一个元素：残留的空格/换行/属性文本全部丢弃
	if ltIdx := strings.Index(rest, "<"); ltIdx >= 0 {
		rest = rest[ltIdx:]
	} else {
		rest = strings.TrimLeft(rest, " \t\r\n")
	}

	rest = strings.ReplaceAll(rest, "&width=0", "")
	rest = strings.ReplaceAll(rest, "&adtype=0", "")

	return []byte(rest), nil
}

// bindToDeviceFunc 返回将 socket 绑定到指定网络设备的 Control 回调（Linux）。
// 仅绑定源 IP 时，出接口仍由路由表决定：在多 WAN（mwan3/负载均衡）环境下，
// 报文可能携带 wan1 的源 IP 却从 wan2 发出，被上游 uRPF 或认证 AC 丢弃，
// 表现为探测/心跳黑洞（无 302 重定向）。SO_BINDTODEVICE 在选路之前强制锁定出接口，
// 使 Linux 行为与 Windows 强主机模型一致。
// 返回 nil 表示设备绑定不可用（非 Linux 平台、设备不存在或无权限），
// 此时退回仅绑定源 IP 的旧行为。
var bindToDeviceFunc = func(ifName string) func(network, address string, c syscall.RawConn) error {
	return nil
}

// NewHttpTransport 根据配置创建HTTP传输层，支持绑定指定网络接口
func NewHttpTransport(c *Config) (http.RoundTripper, error) {
	if c.BindInterface != "" && c.BindInterface != "sys_default" {
		ip, err := GetInterfaceIP(c.BindInterface)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface IP: %w", err)
		}

		localIP := net.ParseIP(ip)
		ifName := c.BindInterface
		resolver := GetResolver(c, localIP)

		// 接口 IP 缓存：DHCP 续约后 IP 可能变化，但不必每次建连都 syscall 查询。
		// 5 秒 TTL 兼顾新鲜度与性能。
		var (
			ipMu      sync.Mutex
			cachedIP  = localIP
			ipChecked time.Time
		)
		freshIP := func() net.IP {
			ipMu.Lock()
			defer ipMu.Unlock()
			if time.Since(ipChecked) < 5*time.Second {
				return cachedIP
			}
			if s, err := GetInterfaceIP(ifName); err == nil {
				if p := net.ParseIP(s); p != nil {
					cachedIP = p
				}
			}
			ipChecked = time.Now()
			return cachedIP
		}

		control := bindToDeviceFunc(ifName)
		return &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{
					LocalAddr: &net.TCPAddr{IP: freshIP()},
					Timeout:   10 * time.Second,
					Resolver:  resolver,
				}
				if control != nil {
					d.Control = control
				}
				return d.DialContext(ctx, network, addr)
			},
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConns:          10,
			DisableKeepAlives:     false,
		}, nil
	} else {
		return &http.Transport{
			DialContext:           (&net.Dialer{Resolver: GetResolver(c, nil), Timeout: 10 * time.Second}).DialContext,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConns:          10,
		}, nil
	}
}

// GetResolver 根据配置返回DNS解析器，支持自定义DNS地址和本地地址绑定
func GetResolver(c *Config, localIP net.IP) *net.Resolver {
	if c.DnsAddress == "" {
		return net.DefaultResolver
	}

	var udpAddr *net.UDPAddr
	if localIP != nil {
		udpAddr = &net.UDPAddr{IP: localIP}
	}

	// 仅当绑定了真实网卡时才锁定设备；sys_default/空 表示用系统默认路由，不锁定
	var control func(network, address string, c syscall.RawConn) error
	if c.BindInterface != "" && c.BindInterface != "sys_default" {
		control = bindToDeviceFunc(c.BindInterface)
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout:   5 * time.Second,
				LocalAddr: udpAddr,
			}
			if control != nil {
				d.Control = control
			}
			return d.DialContext(ctx, "udp", c.DnsAddress)
		},
	}
}
