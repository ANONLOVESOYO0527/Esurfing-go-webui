package main

// Config 客户端认证配置
type Config struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	CheckInterval int    `json:"check_interval"`
	RetryInterval int    `json:"retry_interval"`
	BindInterface string `json:"bind_interface"`
	DnsAddress    string `json:"dns_address"`

	// UserAgent 认证 UA（docs/08 §3）：空或 "auto" → 自动回退链 [2104→2089→2093]；
	// 任意其他值（预设或手输）→ 单元素链不做回退。旧配置文件无此字段 → 零值 → auto，向后兼容
	UserAgent string `json:"user_agent"`
}
