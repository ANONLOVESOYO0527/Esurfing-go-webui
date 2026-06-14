package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// maxJSONBody 限制请求体最大 1MB，防止超大请求造成内存压力
const maxJSONBody = 1 << 20

// API Web API 服务，提供接口管理和日志查询
type API struct {
	manager *Manager
	logHub  *LogHub
}

// NewAPI 创建 API 实例
func NewAPI(manager *Manager, logHub *LogHub) *API {
	return &API{manager: manager, logHub: logHub}
}

// RegisterRoutes 注册 API 路由
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	// recoverMW：捕获 handler panic，避免单请求异常拖垮进程
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					a.logHub.Add(LevelError, fmt.Sprintf("api panic: %v", rec))
					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				}
			}()
			h(w, r)
		}
	}

	mux.HandleFunc("/api/interfaces", wrap(a.handleInterfaces))
	mux.HandleFunc("/api/interfaces/", wrap(a.handleInterfaceAction))
	mux.HandleFunc("/api/settings", wrap(a.handleSettings))
	mux.HandleFunc("/api/logs", wrap(a.handleLogs))
	mux.HandleFunc("/api/logs/stream", wrap(a.handleLogStream))
	mux.HandleFunc("/api/system/interfaces", wrap(a.handleSystemInterfaces))
}

// handleInterfaces 处理 /api/interfaces，GET 查询全部/POST 新增
func (a *API) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.manager.GetAll())

	case http.MethodPost:
		var mc ManagedClient
		if decodeJSON(w, r, &mc) {
			return
		}
		if !validInterfaceName(mc.Name) {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface name"})
			return
		}
		if mc.BindInterface != "" && !validInterfaceName(mc.BindInterface) {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid bind_interface name"})
			return
		}
		if mc.Name == "" {
			mc.Name = mc.BindInterface
		}
		if mc.Name == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "interface name is required"})
			return
		}
		if mc.BindInterface == "" {
			mc.BindInterface = mc.Name
		}
		if err := a.manager.Add(&mc); err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		a.logHub.Add("info", fmt.Sprintf("[%s] added", mc.Name))
		a.writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleInterfaceAction 处理 /api/interfaces/{name}/{action}，支持更新/删除/启用/禁用/登录/注销
func (a *API) handleInterfaceAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/interfaces/")
	parts := strings.SplitN(path, "/", 2)
	name := parts[0]
	if !validInterfaceName(name) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid interface name"})
		return
	}

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	if action == "" {
		switch r.Method {
		case http.MethodPut:
			var mc ManagedClient
			if decodeJSON(w, r, &mc) {
				return
			}
			if mc.BindInterface != "" && !validInterfaceName(mc.BindInterface) {
				a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid bind_interface name"})
				return
			}
			if err := a.manager.Update(name, &mc); err != nil {
				a.writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			a.logHub.Add("info", fmt.Sprintf("[%s] updated", name))
			a.writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

		case http.MethodDelete:
			if err := a.manager.Delete(name); err != nil {
				a.writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
				return
			}
			a.logHub.Add("info", fmt.Sprintf("[%s] deleted", name))
			a.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	switch action {
	case "enable":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := a.manager.Enable(name); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "enabled"})

	case "disable":
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := a.manager.Disable(name); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})

	case "login":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := a.manager.Login(name); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "login started"})

	case "logout":
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := a.manager.Logout(name); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})

	case "force-logout":
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := a.manager.ForceLogout(name); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "force logged out"})

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// handleSettings 处理 /api/settings，GET 查询/PUT 更新全局设置
func (a *API) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.writeJSON(w, http.StatusOK, a.manager.GetSettings())

	case http.MethodPut:
		var s Settings
		if decodeJSON(w, r, &s) {
			return
		}
		if err := a.manager.UpdateSettings(s); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleLogs 查询全部日志
func (a *API) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	a.writeJSON(w, http.StatusOK, a.logHub.GetAll())
}

// handleLogStream SSE 实时日志推送
func (a *API) handleLogStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// 不设置 Access-Control-Allow-Origin：依赖浏览器同源策略，阻止跨站读取日志

	// 豁免 SSE 长连接的 WriteTimeout
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	ch := a.logHub.Subscribe()
	defer a.logHub.Unsubscribe(ch)

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			_, _ = w.Write([]byte(": keepalive\n\n"))
			flusher.Flush()
		case entry, ok := <-ch:
			if !ok {
				return
			}
			_, _ = w.Write(FormatSSE(entry))
			flusher.Flush()
		}
	}
}

func (a *API) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON 读取并解析 JSON 请求体。
// - 限制请求体大小（防止超大请求）
// - 强制要求 Content-Type: application/json（CSRF 防护：simple request 无法伪造非简单类型）
// 返回 true 表示已写入错误响应，调用方应直接 return
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	// Content-Type 校验：仅接受 application/json
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Content-Type must be application/json"})
		return true
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return true
	}
	return false
}

// handleSystemInterfaces 查询系统网络接口列表（排除回环，标记已使用）
func (a *API) handleSystemInterfaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	managed := a.manager.GetNames()
	existing := make(map[string]bool)
	for _, m := range managed {
		existing[m] = true
	}

	ifaces, err := ListInterfaces()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	type SysIface struct {
		Name       string `json:"name"`
		IP         string `json:"ip"`
		IsUp       bool   `json:"is_up"`
		IsLoopback bool   `json:"is_loopback"`
		Hardware   string `json:"hardware"`
		Used       bool   `json:"used"`
	}

	var result []SysIface
	for _, iface := range ifaces {
		if iface.IsLoopback {
			continue
		}
		result = append(result, SysIface{
			Name:       iface.Name,
			IP:         iface.IP,
			IsUp:       iface.IsUp,
			IsLoopback: iface.IsLoopback,
			Hardware:   iface.Hardware,
			Used:       existing[iface.Name],
		})
	}

	a.writeJSON(w, http.StatusOK, result)
}
