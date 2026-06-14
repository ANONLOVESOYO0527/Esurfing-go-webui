// esurfing-go-webui 程序入口，启动 Web 服务和客户端管理器
package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

//go:embed web
var webFS embed.FS

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// privateCIDRs 预定义的私有/本地 CIDR 网段，用于 lan 访问模式白名单
var privateCIDRs = []string{
	"127.0.0.0/8",     // loopback
	"10.0.0.0/8",      // class A private
	"172.16.0.0/12",   // class B private
	"192.168.0.0/16",  // class C private
	"169.254.0.0/16",  // link-local
	"::1/128",         // IPv6 loopback
	"fe80::/10",       // IPv6 link-local
	"fc00::/7",        // IPv6 unique local
}

// accessControl 返回一个中间件，根据访问模式限制来源 IP
// - localhost: 仅允许本机
// - lan: 仅允许私有网段
// - all: 不限制
func accessControl(mode string) func(http.Handler) http.Handler {
	var nets []*net.IPNet
	switch mode {
	case "localhost":
		nets = parseCIDRs([]string{"127.0.0.0/8", "::1/128"})
	case "lan":
		nets = parseCIDRs(privateCIDRs)
	default:
		return func(h http.Handler) http.Handler { return h }
	}
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			ip := net.ParseIP(host)
			if ip == nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			for _, n := range nets {
				if n.Contains(ip) {
					h.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func main() {
	var (
		configPath = flag.String("c", "esurfing_data/config.json", "config file path")
		port       = flag.Int("p", 0, "web server port (overrides config)")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags)

	banner := ` _______  _______  __   __  ______    _______  ___   __    _  _______          _______  _______ 
|       ||       ||  | |  ||    _ |  |       ||   | |  |  | ||       |        |       ||       |
|    ___||  _____||  | |  ||   | ||  |    ___||   | |   |_| ||    ___|        |    ___||   _   |
|   |___ | |_____ |  |_|  ||   |_||_ |   |___ |   | |       ||   | __         |   | __ |  | |  |
|    ___||_____  ||       ||    __  ||    ___||   | |  _    ||   ||  |        |   ||  ||  |_|  |
|   |___  _____| ||       ||   |  | ||   |    |   | | | |   ||   |_| | _____  |   |_| ||       |
|_______||_______||_______||___|  |_||___|    |___| |_|  |__||_______||_____| |_______||_______|`
	fmt.Println(banner)
	log.Println("esurfing-go-webui starting")

	dataDir := filepath.Dir(*configPath)
	if dataDir != "." {
		_ = os.MkdirAll(dataDir, 0755)
	}

	logHub := NewLogHub(1000, filepath.Join(dataDir, "log"))
	manager := NewManager(*configPath, logHub)

	if err := manager.Load(); err != nil {
		log.Printf("warning: failed to load config: %v", err)
	}

	settings := manager.GetSettings()
	webPort := settings.WebPort
	if *port > 0 {
		webPort = *port
	}
	if webPort == 0 {
		webPort = 8080
	}

	// 绑定地址：localhost 模式绑 127.0.0.1，其它模式绑 0.0.0.0
	bindAddr := "0.0.0.0"
	if settings.AccessMode == "localhost" {
		bindAddr = "127.0.0.1"
	}

	api := NewAPI(manager, logHub)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	webSub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Printf("failed to access embedded web files: %v", err)
		manager.StopAll()
		logHub.Close()
		os.Exit(1)
	}

	fileServer := http.FileServer(http.FS(webSub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/favicon.ico", "/icon.svg", "/alpine.min.js":
			fileServer.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	// 应用访问控制中间件（localhost/lan 模式按来源 IP 过滤）
	handler := accessControl(settings.AccessMode)(mux)

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", bindAddr, webPort),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("web server listening on %s:%d (access_mode=%s)", bindAddr, webPort, settings.AccessMode)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	manager.StartEnabled()
	log.Println("enabled clients started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	select {
	case sig := <-sigCh:
		log.Printf("received signal %v, shutting down", sig)
	case err := <-serverErr:
		// 不用 log.Fatal，确保清理逻辑能正常执行
		log.Printf("server error: %v", err)
	}

	// 统一退出清理：停 HTTP 服务 → 停客户端 → 关日志
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
	shutdownCancel()

	manager.StopAll()
	log.Println("all clients stopped")

	logHub.Close()
	log.Println("esurfing-go-webui stopped")
}
