# Esurfing-go-webui

> 基于 [DreamwareN/Esurfing-go](https://github.com/DreamwareN/Esurfing-go) 的带 Web 管理界面的天翼校园网认证客户端

## 简介

Esurfing-go-webui 在原版 Esurfing-go 的基础上，增加了一个基于浏览器的 Web 管理界面，支持通过网页远程管理多个网络接口的认证登录，实时查看日志和连接状态，适用于需要管理多网卡、多账号校园网认证的场景。

## 区别

本项目在 [DreamwareN/Esurfing-go](https://github.com/DreamwareN/Esurfing-go) 的基础上新增了以下功能：

- **Web 管理界面** - 基于浏览器的可视化管理面板
- **RESTful API** - 完整的 HTTP API 接口，便于自动化集成
- **实时日志流 (SSE)** - 通过 Server-Sent Events 实时推送运行日志
- **日志持久化与等级过滤** - 日志自动写入 JSON 文件，支持按等级过滤，自动清理旧日志
- **会话持久化与恢复** - 认证会话信息自动保存，意外退出后可恢复心跳，无需重新认证
- **认证冷却机制** - 多接口认证间自动冷却，避免并发冲突
- **网络黑洞自愈** - 探测超时/非 302 黑洞场景下连续失败自动强制重认证，不再仪等待重定向
- **设备级网卡绑定 (Linux)** - 通过 SO_BINDTODEVICE 锁定出接口，多 WAN 负载均衡下防止报文从错误网卡发出
- **多网卡独立管理** - 每个网络接口独立配置和运行
- **启用/禁用单个接口** - 灵活控制各接口的连接状态
- **三代算法全集（24 个 Algo-ID）** - 旧代 Android 9 + 新代 Android 9（变体 TEA×2/SNOW3G）+ PC 通道 6，覆盖服务端按会话随机轮换的全部算法池
- **自选认证 UA + 自动回退链** - 默认自动链 `2104 → 2089 → 2093`，被拒时自动换下一个重协商；可手选预设或任意自定义 UA（PC 通道/探索 Windows/Mac 族）
- **ZSM 诊断可观测性** - 握手失败时输出 Error-Code / Sub-Error / Server-Tag，用户贴一行日志即可定位是 UA 被拒、算法未知还是网络问题
- **手动登录/登出/强制登出** - 支持手动触发指定接口的认证或断开操作
- **系统网卡自动发现** - 自动检测本机可用网络接口
- **全局设置持久化** - Web 端口、访问模式等全局配置持久化保存
- **Deb / Opkg 包** - 提供 systemd 服务文件和 OpenWrt init 脚本，开箱即用

## 特性

- 基于浏览器的 Web 管理面板，响应式设计
- 支持同时管理多个网络接口的认证会话
- 每个接口独立配置：用户名、密码、网卡绑定、DNS、检查间隔等
- 每接口自选认证 UA（自动回退 / 2104 / 2089 / 2093 / PC / 自定义），会话恢复时沿用登录 UA
- 启用/禁用、手动连接/断开/强制断开单个接口
- 服务启动时自动连接已启用的接口
- 认证会话持久化，意外退出后自动恢复心跳
- 全局认证冷却机制，防止并发冲突
- 实时日志流，支持日志等级过滤
- 日志自动持久化到 JSON 文件，按日期命名，自动轮转清理
- 自动检测本机网络接口
- 全局设置：Web 端口、访问模式、默认最大重试次数、认证冷却时间、日志等级
- 接口支持排序，配置自动持久化到 JSON 文件
- 支持 Linux / Windows / macOS / OpenWrt
- 提供 systemd 服务文件和 OpenWrt init 脚本
- 单二进制文件，前端资源内嵌，零外部依赖

## 快速开始

### 1. 获取程序

**方式一：下载预编译二进制**

从 [Releases](https://github.com/DreamwareN/Esurfing-go-webui/releases) 页面下载对应平台的二进制文件。

**方式二：从源码编译**

```bash
git clone https://github.com/DreamwareN/Esurfing-go-webui.git
cd Esurfing-go-webui
go build -trimpath -ldflags="-s -w" -o esurfing-go-webui .
```

要求 Go 1.25.3 或更高版本。

### 2. 运行

```bash
# 使用默认配置 (端口 8080)
./esurfing-go-webui

# 指定配置文件
./esurfing-go-webui -c /path/to/config.json

# 指定 Web 端口
./esurfing-go-webui -p 9090
```

启动后在浏览器中打开 `http://<设备IP>:8080` 即可访问管理界面。

## CLI 参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-c` | 配置文件路径 | `esurfing_data/config.json` |
| `-p` | Web 服务端口 (覆盖配置文件中的设置) | 使用配置文件中的值，未设置则为 `8080` |

## 配置文件

配置文件为 JSON 格式，结构如下：

```json
{
  "interfaces": [
    {
      "interface": "wan0",
      "enabled": true,
      "username": "10001234",
      "password": "12345678",
      "check_interval": 10000,
      "retry_interval": 10000,
      "bind_interface": "eth0",
      "dns_address": "119.29.29.29:53",
      "max_retries": 5,
      "order": 1
    },
    {
      "interface": "wan1",
      "enabled": false,
      "username": "10005678",
      "password": "87654321",
      "user_agent": "CCTP/Linux64/1003",
      "check_interval": 10000,
      "retry_interval": 10000,
      "bind_interface": "eth1",
      "dns_address": "",
      "max_retries": 5,
      "order": 2
    }
  ],
  "settings": {
    "web_port": 8080,
    "default_max_retries": 5,
    "access_mode": "all",
    "auth_cooldown": 5,
    "log_level": "info"
  }
}
```

### 接口配置字段

| 字段 | 说明 |
|------|------|
| `interface` | 接口名称标识 |
| `enabled` | 是否在服务启动时自动连接 |
| `username` | 认证用户名 |
| `password` | 认证密码 |
| `user_agent` | 认证 UA（见下）：空/`auto` = 自动回退链 `2104 → 2089 → 2093`；预设或任意自定义 UA（≤64 字符）= 固定使用不回退。旧配置无此字段 → 自动链，向后兼容 |
| `check_interval` | 网络状态检查间隔 (毫秒)，默认 `10000` |
| `retry_interval` | 登录失败重试间隔 (毫秒)，默认 `10000`，负值表示不重试 |
| `bind_interface` | 绑定的网卡设备名称 (如 `eth0`、`enp0s1`、`wan0`)，留空使用系统默认 |
| `dns_address` | 自定义 DNS 服务器地址 (需带端口号，如 `119.29.29.29:53`)，一般留空即可 |
| `max_retries` | 最大重试次数 |
| `order` | 接口显示排序序号，数值小的排在前面 |

### user_agent 字段说明（认证 UA 与算法池）

服务器按 UA 家族分派算法池且按会话随机轮换，本项目已内置全部三代 24 个算法：

| UA | 算法池 |
|---|---|
| `CCTP/android11_64/2104` | 新代 9 算法（含变体 TEA×2 / SNOW3G） |
| `CCTP/android64_vpn/2089` / `2093` | 旧代 9 算法 |
| `CCTP/Linux64/1003` | PC 通道 6 算法 |
| 其他（如 `CCTP/WinSVR5/1068`） | 未知算法族：准入可能通过，但下发未知 GUID 时会明确报错并回退 |

自动链被拒时（Error-Code 3）自动换下一个 UA 重新走完整认证链（每轮全新会话），
成功后记忆该 UA 并写入会话文件，恢复会话/心跳/下线报文全程沿用。

### 全局设置字段

| 字段 | 说明 | 可选值 |
|------|------|--------|
| `web_port` | Web 服务端口 | 正整数，默认 `8080` |
| `default_max_retries` | 新建接口时的默认最大重试次数 | 正整数，默认 `5` |
| `access_mode` | 访问控制模式 | `all` (允许所有)、`lan` (仅局域网)、`localhost` (仅本地) |
| `auth_cooldown` | 多接口认证冷却时间 (秒)，防止并发冲突 | 1-600，默认 `5` |
| `log_level` | 日志最低等级，低于此等级的日志不显示 | `debug`、`info`、`warn`、`error`，默认 `info` |

## Web 管理界面

### 列表面板

- 以卡片形式展示所有已配置的网络接口
- 每个接口显示：名称、状态、用户 IP、上次登录时间、心跳信息、错误计数
- 状态类型：`online` (在线) / `offline` (离线) / `auth` (认证中) / `disabled` (已禁用)
- 支持的操作：启用/禁用、手动连接/断开/强制断开、编辑、删除
- 列表每 15 秒自动刷新

### 更多设置

- 查看和修改全局设置 (Web 端口、最大重试次数、访问模式、认证冷却时间、日志等级)
- 实时日志查看，支持 SSE 推送，可按日志等级过滤

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/interfaces` | 获取所有接口列表 |
| `POST` | `/api/interfaces` | 添加新接口 |
| `PUT` | `/api/interfaces/{name}` | 更新接口配置 |
| `DELETE` | `/api/interfaces/{name}` | 删除接口 |
| `POST` | `/api/interfaces/{name}/enable` | 启用接口 |
| `DELETE` | `/api/interfaces/{name}/disable` | 禁用接口 |
| `POST` | `/api/interfaces/{name}/login` | 手动触发登录 |
| `DELETE` | `/api/interfaces/{name}/logout` | 手动登出 |
| `DELETE` | `/api/interfaces/{name}/force-logout` | 强制登出 |
| `GET` | `/api/settings` | 获取全局设置 |
| `PUT` | `/api/settings` | 更新全局设置 |
| `GET` | `/api/logs` | 获取全部日志 |
| `GET` | `/api/logs/stream` | SSE 实时日志流 |
| `GET` | `/api/system/interfaces` | 获取本机网络接口列表 |

## 部署

### Linux

适用于 Debian / Ubuntu 等使用 systemd 的发行版：

```bash
# 安装 Deb 包 (从 Releases 下载)
sudo dpkg -i esurfing-go-webui_*_amd64.deb

# 安装后会自动注册并启动服务
# 查看服务状态
sudo systemctl status esurfing-go-webui

# 手动管理服务
sudo systemctl start esurfing-go-webui
sudo systemctl stop esurfing-go-webui
sudo systemctl restart esurfing-go-webui

# 查看日志
sudo journalctl -u esurfing-go-webui -f
```

Deb 包安装后文件位置：
- 二进制文件：`/usr/bin/esurfing-go-webui`
- 配置文件：`/etc/esurfing-webui/config.json`
- 数据目录：`/var/lib/esurfing-webui`
- 服务文件：`/lib/systemd/system/esurfing-go-webui.service`

### OpenWrt

```bash
# 安装 ipk 包 (从 Releases 下载)
opkg install esurfing-go-webui_*_*.ipk

# 服务会自动启动
# 手动管理服务
/etc/init.d/esurfing-go-webui start
/etc/init.d/esurfing-go-webui stop
/etc/init.d/esurfing-go-webui restart
```

### Windows / macOS

直接运行下载的二进制文件即可：

```cmd
:: Windows
esurfing-go-webui.exe -c config.json
```

```bash
# macOS
./esurfing-go-webui -c config.json
```

## 支持的平台

| 操作系统 | 架构 |
|----------|------|
| Linux | amd64, arm (v7), arm64, mips, mipsle, mips64, mips64le, riscv64 |
| Windows | amd64, arm64 |
| macOS | amd64, arm64 |

Deb 包支持：amd64, armhf, arm64

Opkg 包支持：x86_64, arm_cortex-a9, aarch64, mips_24kc, mipsel_24kc

## 项目结构

```
Esurfing-go-webui/
├── main.go            # 程序入口，HTTP 服务器，前端嵌入，生命周期管理
├── client.go          # 认证客户端核心逻辑，网络检查与心跳维持，UA 回退链状态机
├── auth.go            # 认证流程：学校信息、配置、ZSM 握手（含 Error-Code 诊断）、票据、登录
├── cipher.go          # 第一代算法实现 (AES/3DES/SM4/ZUC/XTEA) + 注册表主体
├── cipher_new.go       # 第二代 PC 6 算法 + 第三代映射组注册（参数化构造器，注册表 init() 追加）
├── cipher_tea.go      # 变体 TEA 三层 ECB/CBC（第三代移植组 + PC XTEA/TEA 共用块函数）
├── cipher_snow3g.go   # SNOW3G 变体流密码（第三代移植组，逐语句移植）
├── cipher_test.go     # KAT 对拍 + 24 ID roundtrip + 映射组交叉断言
├── request.go         # HTTP 请求构造，自定义请求头与校验
├── xml.go             # XML 报文生成与解析，UA 预设表
├── utils.go           # 工具函数：网卡 IP 获取、DNS 解析、随机数生成、设备级绑定入口
├── utils_linux.go     # Linux SO_BINDTODEVICE 设备级网卡绑定（多 WAN 选路锁定）
├── api.go             # RESTful API 路由与处理函数
├── manager.go         # 接口管理器：客户端生命周期、配置持久化、认证冷却
├── session.go         # 会话持久化与恢复：认证信息保存/加载/删除
├── loghub.go          # 日志中心：内存存储、SSE 广播、文件持久化、等级过滤
├── interfaces.go      # 系统网络接口发现
├── config.go          # 认证配置结构定义（含 user_agent）
├── testdata/kat/      # KAT 真值（15 文件，新代 9 + PC 6，由独立 oracle 生成）
├── go.mod             # Go 模块依赖
├── web/
│   └── index.html     # 单页前端界面 (HTML/CSS/JS 一体)
├── esurfing_data/     # 运行时数据目录
│   ├── config.json    # 配置文件
│   ├── log/           # 日志文件 (JSON 格式，按日期命名)
│   └── sessions/      # 认证会话持久化文件
├── winres/
│   └── winres.json    # Windows 可执行文件资源嵌入配置
├── packaging/
│   ├── make_ipk.py    # OpenWrt ipk 包构建脚本
│   ├── deb/
│   │   └── esurfing-go-webui.service   # systemd 服务文件
│   └── opkg/
│       └── esurfing-go-webui           # OpenWrt init 脚本
└── .github/
    └── workflows/
        └── build.yml   # CI/CD 自动构建与打包
```

## 认证流程

```
网络检测 (HTTP 204 检查)
    │
    ├─ 204 → 网络正常，等待下次检查
    │
    └─ 302 → 捕获重定向，进入认证流程
                │
                ├─ 0. 解析 UA 回退链（auto：2104 → 2089 → 2093；每轮尝试全新会话）
                ├─ 1. GetSchoolInfo()    获取学校/区域信息
                ├─ 2. GetEConfig()       获取认证服务器配置
                ├─ 3. GetUserAndAcIP()   解析用户 IP 与 AC IP
                ├─ 4. GetAlgoId()        获取加密算法 ID（ZSM 握手，携带诊断信息）
                ├─ 5. NewCipher()        选择加密算法（未知 GUID → 换下一个 UA 重试）
                ├─ 6. GetTicket()        获取认证票据
                └─ 7. Login()            执行登录
                        │
                        └─ 登录成功 → 记忆成功 UA → 启动心跳保活
```

## 算法来源与验证

CCTP 协议在 ZSM 握手时下发算法 GUID（Algo-ID），**服务器按 UA 家族分派算法池、且池内按会话随机轮换**，
因此客户端必须实现整个算法池全集——本仓库内置全部三代 24 个算法，任何一次认证随机轮换到哪个都能闭环。

### 算法全景（三代 24 个 Algo-ID）

| 代际 | 通道 | 数量 | 算法 | 实现文件 |
|---|---|---|---|---|
| 第一代（旧 Android） | `CCTP/android64_vpn/2089`、`2093` | 9 | 双层 AES-CBC/ECB、双层 3DES-CBC/ECB、ZUC 流、SM4-CBC/ECB、XTEA 三层、XTEA-IV 三层 CBC | `cipher.go` |
| 第二代（PC） | `CCTP/Linux64/1003` | 6 | DES 六层 ECB（`B306E770`）、双层 3DES-CBC（层序与 Android 相反）、双层 AES-ECB/CBC、XTEA 三层、变体 TEA 三层 CBC（`AB6C8EBE`） | `cipher_new.go` |
| 第三代（新 Android） | `CCTP/android11_64/2104` | 9 | **映射组 6**：结构归约证明=旧代标准基元换 GUID（密钥复用）；**移植组 3**：变体 TEA 三层 ECB/CBC、SNOW3G 变体流（自研结构，与标准库不同源） | `cipher_new.go` / `cipher_tea.go` / `cipher_snow3g.go` |

### 来源与谱系

| 代际   | 参考实现                                                                                                                                                               | 验证方式                                                                       |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| 旧代 9 | 社区逆向谱系（[Esurfing-go](https://github.com/DreamwareN/Esurfing-go) / [EsurfingClient_Android](https://github.com/Ironjhin/EsurfingClient_Android)）                    | 本仓库 mock e2e                                                               |
| 新代 9 | [Ironjhin/EsurfingClient_Android](https://github.com/Ironjhin/EsurfingClient_Android) @ `0ffbf00`                                                                  | 映射组 6 个与标准 AES/DES/SM4 向量对拍一致；移植组 3 个逐语句移植 + KAT 对拍；`319FC5AB` 经真实服务器全链路确证 |
| PC 6 | [BadGhost520/ESurfingClient-CVersion](https://github.com/BadGhost520/ESurfingClient-CVersion)（[esp32_esurfing](https://github.com/MYHealer/esp32_esurfing) 同源交叉验证） | KAT 对拍；`B306E770`/`AB6C8EBE` 所在 PC 池经真实服务器全链路验证                            |

协议谱系：Rsplwe/ESurfingDialer（Kotlin 原始实现，已删库）→ Esurfing-go / C 版各分支 → 本项目。

### 密钥来源

全部算法的密钥与 IV 均为**协议固定常量**（逆向自官方客户端内置映射表），并非用户密钥。
第三代密钥与第一代逐字节同源（部分密钥 blob 顺序反转拆分）——服务器的换代手法是换 GUID +
把基元改成“看起来非标准”的结构变体，而密钥材料不变。安全强度说明见[安全注意事项](#安全注意事项)。

### 验证体系（四层）

| 层 | 内容 |
|---|---|
| L1 · KAT | `testdata/kat/*.json`（15 文件，真值由独立转录 C 参考源的 Python oracle 生成），Go 实现加解密**双向逐字节对拍**，另含映射组“新 GUID 输出 == 旧 GUID 输出”交叉断言与密钥镜像等价性检查（`cipher_test.go`） |
| L2 · Mock e2e | 24 个算法 ID 全链路闭环（握手→票据→登录→心跳），负样本与 UA 回退链行为断言（`auth_test.go`） |
| L3 · 实战 | 三条通道在真实校园网全链路验证（2026-09）：PC 通道（`B306E770`）、新代 phone 通道（UA 2104 → `319FC5AB`）、旧代 phone 通道（UA 2089 → `B809531F`）——我方加密报文被服务器正确解密受理，服务器密文被我方正确解密 |
| 回归红线 | 旧 9 个 GUID 的注册项与实现一行未动（新算法经 `cipher_new.go` 的 `init()` 追加注册），旧配置文件/旧会话文件完全向后兼容 |

### 出处与许可说明

- 第三代真变体（变体 TEA×2 / SNOW3G）为**照规格独立转录的 Go 实现**（逐语句对齐 C 参考源的控制流，非工程代码复制）；上游参考仓库
  [Ironjhin/EsurfingClient_Android](https://github.com/Ironjhin/EsurfingClient_Android) 未附 LICENSE 文件，故按惯例在文档中明确注明算法行为参考来源。
- 若以二进制形式分发，建议在发行说明中保留本节出处信息。

## 依赖

| 依赖 | 用途 |
|------|------|
| [github.com/emmansun/gmsm](https://github.com/emmansun/gmsm) | SM4 / ZUC 国密算法实现 |
| [github.com/google/uuid](https://github.com/google/uuid) | 生成 Client-ID |

## DNS 说明

当系统使用 DNS-over-HTTPS (DoH) 时，未认证状态下 DoH 无法工作，会导致认证所需域名解析失败。此时需要在接口配置中手动指定 `dns_address`，一般填写 DHCP 获取的 DNS 地址即可（需带端口号，如 `119.29.29.29:53`）。

## 安全注意事项

> 以下为部署时需要了解的安全相关限制，请务必阅读。

- **`access_mode` 留空等价于 `all`**：配置文件中 `access_mode` 字段为空时，Web 服务会绑定 `0.0.0.0` 且**不限制来源 IP**，同网任意设备均可访问管理 API。请显式设置为 `localhost`（仅本机）或 `lan`（仅局域网私网网段），切勿在不可信网络中留空或使用 `all`。
- **反向代理部署需注意**：若在 nginx 等反代后部署，`access_mode` 的来源 IP 过滤基于 `RemoteAddr`（即反代地址，通常是 `127.0.0.1`），`localhost`/`lan` 模式会**实际放行所有经反代进来的流量**。如需在反代后使用，请自行在反代层做访问控制或鉴权。
- **加密算法为协议固定密钥**：各 `cipher*.go` 中 24 个算法（AES/3DES/SM4/XTEA/TEA 变体/ZUC/SNOW3G 变体）的密钥与 IV 均为逆向官方客户端得到的固定值，且 ZUC 等流密码使用固定密钥流。这些加密仅用于满足服务器协议校验、防止被简单爬虫伪造，**不具备防窃听/防篡改的安全强度**，不要将其视为安全通道。算法来源详见[算法来源与验证](#算法来源与验证)。

## 致谢

- [DreamwareN/Esurfing-go](https://github.com/DreamwareN/Esurfing-go) - 原版 Esurfing-go 认证客户端
- [Rsplwe/ESurfingDialer](https://github.com/nicai1900/ESurfingDialer) - 原始参考实现
- [Ironjhin/EsurfingClient_Android](https://github.com/Ironjhin/EsurfingClient_Android) - 第三代新算法参考实现
- [BadGhost520/ESurfingClient-CVersion](https://github.com/BadGhost520/ESurfingClient-CVersion) - PC 通道算法参考实现
- [MYHealer/esp32_esurfing](https://github.com/MYHealer/esp32_esurfing) - PC 算法同源交叉验证

## 许可证

[Apache License 2.0](LICENSE)
