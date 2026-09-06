# dpi-probe

[English](README.md) | [Français](README.fr.md) | [Русский](README.ru.md) | [简体中文](README.zh.md)

**1.0.0-beta.1** 是终端网络诊断工具集，覆盖 DNS 异常、TCP、TLS/SNI、HTTP Host、ECH、连接重置、分段及路径差异。VLESS/REALITY 诊断只是其中一个专用模块。

工具用于收集观察结果、定位连接失败的阶段，并提出下一步验证方法。超时不能证明存在 DPI，RST 不能确定注入者。两端抓包可以将差异限定在观察点之间，不能确定具体是哪台路由器实施了过滤。

## 适用场景

| 场景 | 可以获得的帮助 |
|---|---|
| 移动网络可用，家庭宽带不可用 | 对同一目标使用相同参数，比较 DNS、TCP 和 TLS。 |
| 怀疑 DNS 污染 | 对比本地与参考解析结果，同时考虑 CDN 差异及参考解析器不可达。 |
| TCP 成功但 TLS 无响应 | 改变 SNI、TLS 字段及 TCP 写入分段，观察响应差异。 |
| 想知道 ECH 是否可用 | 区分 DNS HTTPS 记录发布情况与兼容 curl 发起的强制 ECH 请求。 |
| 连接重置或单向传输 | 分析两端抓包中的序列号范围、ACK 及 FIN/RST 顺序。 |
| VLESS/REALITY 失败 | 结合 sing-box 配置、日志、路由和抓包，列出失败阶段、可能原因及缺失证据。 |

## 安装与启动

下载并解压仓库。Windows 双击 **`dpi-probe.cmd`**；Linux 在项目目录中执行 **`sh dpi-probe.sh`**。

启动器检查 Python 3.11+，询问是否创建 `.venv` 并安装 `requirements.txt`，然后检查 TShark 和抓包接口。每次安装都需要用户回答。Windows 可通过 winget 安装 Python 3.13 和 Wireshark，请完成交互安装并包含 TShark 和 Npcap。没有 winget 时，从官方网站安装 Python 后重新启动。Debian/Ubuntu 在支持时使用 apt，其他系统提供手动说明。安装可能需要管理员权限。

必需的 Python 模块为 `cryptography` 和 `dnspython`。缺失或版本不兼容时停止执行。拒绝安装 TShark 后仍可进行不依赖抓包的测试；明确要求抓包而条件不足时会报错，不会将依赖缺失解释为网络过滤。Wireshark 图形界面便于人工查看，自动化依赖的是 TShark。

| 功能 | 依赖 |
|---|---|
| 菜单、核心测试、报告 | Python 3.11+、venv/pip、requirements.txt |
| PCAP 分析 | TShark |
| 实时抓包 | TShark、Windows 上的 Npcap 或 Unix 上的 libpcap、抓包权限 |
| 主动 ECH | 支持 `--ech hard` 的 curl 构建，仅安装普通 curl 不足以保证支持 |
| 反向路由跟踪 | SSH 及具有 traceroute/tracert 的受控远端主机 |

Windows 手动安装：

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python main.py --doctor
.venv\Scripts\python main.py
```

Linux 使用 `python3 -m venv .venv` 创建环境，之后将 Python 路径替换为 `.venv/bin/python`。必要时安装发行版的 venv/pip 包。`--doctor` 只检查本地依赖，不发送网络探测；退出码 2 表示核心或抓包依赖不足。能够列出接口不代表一定具有抓包权限。

Windows 已在本地测试，Linux 纳入 CI；真实 Linux/OpenWrt 硬件上的现场验证仍待完成。OpenWrt 建议使用 tcpdump 短时抓包，再在电脑上分析。路由器完整安装仍属实验性，取决于内存、架构和软件包。启动器不更改路由或防火墙。

## 交互菜单

首次启动可选择英语、法语、俄语或简体中文，之后通过选项 6 修改。用户配置目录中只保存语言代码。菜单和输入提示已翻译，技术输出与报告尚未完全本地化。安装提示目前使用英语/法语。

1. 常规诊断：快速、完整或自选测试；完整运行可选择抓包。
2. VLESS/REALITY 诊断。
3. 高级工具：两端抓包对比、被动/主动 ECH、接口列表。
4. 比较两份详细报告。
5. 生成供自愿分享的精简报告。
6. 修改语言；0 退出。

完整测试覆盖 TCP/443、HTTP、SNI、TTL、RST、畸形 TLS、目标地址差异、HTTP Host、DNS、TCP 写入分段、TLS 变体、手工构造 ClientHello 的指纹、TLS 字段变异及 ECH 发布情况。历史模块名称中的“bypass”和“fragmentation”不表示已验证应用层绕过或 IP 分片。完整运行可能需要数分钟。`--samples` 仅重复支持采样的探测，不会重复所有操作。

## 命令行使用

请使用虚拟环境中的 Python。无参数运行需要交互终端；`--auto` 显式启动快速自动模式。

```text
python main.py --help
python main.py --version
python main.py --auto
python main.py 1.1.1.1 --samples 3 --profile direct
python main.py 1.1.1.1 --samples 3 --profile alternate --pcap --pcap-interface 3
python main.py --multi --samples 3
python main.py --compare reports/direct.json reports/alternate.json
python main.py --ech example.com
python main.py --ech example.com --ech-active
python main.py --anonymize reports/direct.json
```

将 3 替换为高级菜单列出的接口编号。完整运行的抓包只针对目标的 443 端口，不涵盖所有 DNS 或其他目标流量。`targets.json` 设置 IPv4 目标与域名组。默认公共 anycast 地址不是本项目控制的服务器，也不是所有 SNI 对应的权威 TLS 服务。`blocked`/`clean` 仅为历史测试分组，不是已证实的屏蔽分类。需要归因时应优先使用受控端点，并仅进行获准的主动测试。

主动 ECH 使用 curl 的 `--ech hard`、Cloudflare DoH 和证书验证，禁用环境变量中的 HTTP 代理。成功、不支持、未满足 ECH 要求和传输错误分别记录。TUN 路由仍然可能生效。DNS 发布并不证明服务器接受 ECH，ECH 失败本身也不能证明过滤。

### 隧道诊断与两端抓包

```text
python main.py --diagnose-tunnel --sing-box-config config.json --outbound-tag reality --sing-box-log client.log --tunnel-endpoint SERVER_IP:443 --tunnel-pcap client.pcapng --server-pcap server.pcapng --diagnosis-output reports/incident.json
python main.py --dual-pcap client.pcapng server.pcapng --tunnel-endpoint SERVER_IP:443 --flow-output reports/paired.json
tshark -D
tshark -i 3 -f "host SERVER_IP and tcp port 443" -a duration:30 -w client.pcapng
tcpdump -i any -s 0 -w server.pcap 'tcp port 443'
```

替换示例参数，省略不存在的可选文件，并选择具有唯一 tag 的 outbound。分析历史抓包时，应指定当时实际使用的服务器 IP。两端时钟应同步，并记录同一次复现。菜单抓包要求用现有客户端复现连接；dpi-probe 不实现 REALITY 身份验证。普通 TLS 成功可能只是 fallback 响应。

`--active-tunnel-checks` 增加服务器 TCP 与路由跟踪检查。Windows 的 `--underlay-interface-index N` 为 TCP 探测选择物理接口，其系统索引不同于 TShark 编号。路由快照不能证明所有探测均绕开 TUN。可用 `--sing-box-api http://127.0.0.1:9090 --sing-box-secret-env VARIABLE_NAME` 查询本地 API；拒绝远程 URL 与重定向。

反向跟踪需要您控制的远端代理：

```text
python main.py --reverse-trace PUBLIC_IP --reverse-agent probe@CONTROLLED_HOST
```

## 报告、隐私与限制

常规详细报告与隧道报告同时保存 JSON 和 Markdown。快速、ECH、两端抓包输出采用不同格式，并非都可交给详细报告比较器。默认保存在 `reports/`，可用相应输出参数指定路径。没有自动上传或持续监控。

NAT、非对称路由、offload、不完整抓包和抓包丢失均会影响解释。匹配依据是 TCP 特征和序列号范围，不验证负载内容真实性。缺失范围不能直接换算为实际网络丢包率。

原始抓包、配置与日志可能暴露地址、域名和凭据。常见秘密字段的脱敏并不全面。精简隧道导出保留诊断代码，常规导出仍保留已测试域名。分享前请检查内容。Git 忽略报告、日志、抓包及虚拟环境。

## 验证与版本状态

```text
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m coverage run --source=src -m pytest -q
python -m coverage report --omit="src/probes/*" --fail-under=40
python -m compileall -q main.py bootstrap.py src
python main.py --help
git diff --check
```

测试覆盖报告结构、诊断回归、菜单、语言，并在 TShark 可用时使用真正的 TShark 分析合成 PCAP。缺少可选集成工具时会明确跳过。这不代表已验证所有运营商上的诊断准确性。受控现场测试、更多平台安装验证及母语审校完成前保持 beta 状态。

参见[技术审计](AUDIT_TECHNIQUE.md)、[更新记录](CHANGELOG.md)、[研究路线图](ROADMAP_RECHERCHE.md)、[MIT 许可证](LICENSE)。官方参考：[Python](https://www.python.org/downloads/)、[Windows Wireshark 安装](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html)、[curl ECH 参数](https://curl.se/docs/manpage.html#--ech)。
