# 26.11.6.1 — 多平台优化验证版

基于上游 `26.09.3.2`，针对小内存路由器的日志开销和运行稳定性改进。

## 变化

- 内存日志改为固定容量循环历史，仍保留最近 1000 条、时间顺序、实时推送和文件记录。
- 调试日志关闭时提前跳过格式化和系统日志写入，启用的消息只格式化一次。
- 日志约 128 KiB 轮转，最多保留 3 个文件（包含当前文件）；时钟回拨时保护正在写入的日志。
- 网络探测失败显示“检测异常”，一次抖动不会因此强制重新认证。
- HTTP 请求设置 30 秒全过程超时，客户端登出后释放旧空闲连接。
- **网页每 15 秒刷新、已配置的网络探测/重试参数及服务端心跳规则保持不变。**
- 旧多平台工作流改为手动构建，产物保存在 Actions 中，避免覆盖本次验证过的发布附件。

## 下载与安装

| 系统或安装包 | 提供的架构 |
| --- | --- |
| Linux 独立程序 | amd64、arm（ARMv7）、arm64、mips、mipsle、mips64、mips64le、riscv64 |
| Windows `.exe` | amd64、arm64 |
| macOS 独立程序 | amd64（Intel）、arm64（Apple Silicon） |
| Debian / Ubuntu `.deb` | amd64、armhf、arm64 |
| OpenWrt `.ipk` | x86_64、arm_cortex-a9、aarch64_generic、mips_24kc、mipsel_24kc |

- 文件名中的架构必须与设备及系统匹配；Linux MIPS 系列使用 softfloat，ARM 32 位版本使用 ARMv7。
- OpenWrt 软件包的架构必须出现在设备的 `opkg print-architecture` 列表中。ARM64 包使用标准名称 `aarch64_generic`，不再沿用旧流程的 `aarch64`；其他 ARM64 固件可选择适合其环境的独立程序，请勿强制忽略包架构检查。
- `SHA256SUMS.txt`：下载文件校验值；`LICENSE.txt`：Apache-2.0 许可证。

软件包不包含账号、密码、会话或个人配置。安装/升级会重启认证服务，校园网可能短暂断开。请先备份 `/etc/esurfing-webui/` 和可用的旧程序，并准备备用联网方式。

```sh
opkg install ./esurfing-go-webui_26.11.6.1_mipsel_24kc.ipk
```

## 验证范围和限制

- 小米 4C、OpenWrt 23.05.3 上，同一应用代码已完成认证、连续联网探测、网页接口、DNS 和开机自启验证。
- 完整 Go 测试套件（67 个顶层测试）和静态检查通过；另有 6 项 BusyBox 隔离恢复测试通过。
- 相同 Windows/amd64 环境下，满日志历史的局部基准从每条约 122,912 字节临时分配降到 32 字节。这不代表校园网带宽或总 RSS 的同等改善。
- 短时路由器 RSS 没有显示下降，长期稳定性仍需观察；其他硬件、系统及校园网尚未实测，因此此版标记为 **Pre-release**。
- 本地 Windows race 检测程序无法启动，不能声称 race 检测通过。
- 10 MiB 响应体上限暂未缩小，避免在缺少实际响应尺寸证据时影响兼容性。
- 发布文件从公开发布提交重新构建，其校验值以本页附件为准；设备上验证的是相同应用代码的先前构建。
- 补充的其他平台已通过 GitHub Actions 构建、文件架构和安装包内容检查，但没有对应设备的实机运行验证。已有 MIPS 小端程序和安装包保持原校验值。

## 安全说明

火绒曾将上游原版 Linux 程序识别为 `Trojan/Linux.Agent.bo`。本次优化构建在发布准备时也再次被火绒删除，后一次检测的具体名称尚未核实。原版被检文件哈希与上游公开发行文件一致，但这不能证明安全，也没有厂商误报结论。本版不宣称已获得安全认证，不建议关闭防护或添加整盘排除。

## 来源与构建

保留原项目 Apache-2.0 许可证及提交历史；上游为 `EchoPing07/Esurfing-go-webui`，本版由 `ANONLOVESOYO0527/Esurfing-go-webui` 发布。

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat \
  go build -trimpath -ldflags="-s -w -X main.version=26.11.6.1" -o build/router .
python3 packaging/build_router_release.py --binary build/router --version 26.11.6.1 --output dist
```

构建使用 Go 1.25.3。补充多平台的构建流程见 [Actions 运行记录](https://github.com/ANONLOVESOYO0527/Esurfing-go-webui/actions/runs/42242685474)，构建提交为 `0f74231`，与版本标签相比只修改构建工作流，应用源码一致。版本标签保持不变；源码分支中的本说明包含后续补充记录。
