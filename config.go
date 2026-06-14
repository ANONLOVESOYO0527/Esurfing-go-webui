package main

// Config 客户端认证配置
type Config struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	CheckInterval int    `json:"check_interval"`
	RetryInterval int    `json:"retry_interval"`
	BindInterface string `json:"bind_interface"`
	DnsAddress    string `json:"dns_address"`
}
