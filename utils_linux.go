//go:build linux

package main

import (
	"net"
	"syscall"
)

func init() {
	// Linux：用 SO_BINDTODEVICE 将 socket 锁定到指定网络设备。
	// 仅绑定源 IP 不足以锁定出接口——多 WAN 负载均衡下报文仍按路由表选路，
	// 可能“源 IP 是 wan1、包从 wan2 出”，被上游 uRPF/AC 丢弃形成黑洞。
	//
	// 权限与兼容性处理：
	// - SO_BINDTODEVICE 需要 CAP_NET_RAW（root 或相应 capability）；
	//   OpenWrt init 脚本以 root 运行，通常具备。
	// - 探测阶段验证设备名是否有效，无效（如已改名的网卡）返回 nil，
	//   退回仅绑源 IP 的旧行为，避免整体瘫焥。
	bindToDeviceFunc = func(ifName string) func(network, address string, c syscall.RawConn) error {
		// 设备不存在时直接降级，避免每次建连都收到 ENODEV
		if _, err := net.InterfaceByName(ifName); err != nil {
			return nil
		}
		return func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName)
			})
			if err != nil {
				return err
			}
			if sockErr != nil {
				// EPERM（无 CAP_NET_RAW）等：降级为不绑定设备，连接仍可建立
				return nil
			}
			return nil
		}
	}
}
