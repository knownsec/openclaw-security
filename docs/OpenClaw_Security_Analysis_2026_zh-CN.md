# 一、背景说明

随着 AI Agent 技术的快速演进，具备自动化决策与自主执行能力的开源框架正逐步进入真实业务场景与生产环境。相较于传统应用系统，这类框架不仅承担数据处理与接口调用任务，还具备执行本地命令、访问系统资源以及调度外部服务的能力，其系统权限边界与安全模型呈现出更高复杂度。

OpenClaw 作为开源 AI Agent 生态中的代表性项目之一，在 2026 年初迅速获得全球开发者社区关注。该项目以聊天机器人形态运行，支持通过 Web 页面及即时通讯工具输入自然语言指令，实现包括邮件处理、日程管理、浏览器控制、文件操作乃至 Shell 命令执行等高权限任务。凭借本地化部署能力与较强的自主执行特性，项目在短时间内实现了用户规模与社区影响力的快速增长。

OpenClaw 具备以下核心能力特征：

* 自然语言驱动任务执行
* 调用本地或远程工具接口
* 访问文件系统与网络资源
* 集成第三方插件与技能扩展机制

这些能力在提升自动化效率和可扩展性的同时，也意味着其具备较高系统权限与广泛资源访问能力。与传统 Web 应用相比，AI Agent 框架的安全问题不再局限于单一接口漏洞或配置错误，而呈现出更加立体的风险结构，包括：

* 控制接口暴露风险
* 执行层权限滥用风险
* 插件生态与供应链风险
* 部署配置与信任边界问题

在快速扩张的开源生态背景下，安全治理机制往往滞后于功能演进节奏，导致阶段性风险集中暴露。因此，有必要对 OpenClaw 当前的安全现状与公开安全事件进行系统性梳理与客观分析。

# 二、项目演进与攻击面变化

## 2.1 项目发展简述

OpenClaw 起源于轻量级自动化转发工具原型，随后逐步演进为具备任务调度与插件扩展能力的完整 AI Agent 框架。在发展过程中，项目经历阶段性品牌调整，并最终定名为 OpenClaw。相关名称争议曾涉及 Anthropic，随着项目关注度快速增长，插件生态与社区规模同步扩大。

## 2.2 架构演进带来的攻击面扩展

OpenClaw 采用分层架构：

* 输入接口层（Web / API / 消息渠道）
* 决策层（大模型驱动）
* 执行层（命令与工具调用）
* 插件生态层（第三方技能）

![architecture](./images/architecture.png)

随着插件数量增加与执行能力增强，其攻击面呈现以下特征：

1. 控制接口暴露风险增加
2. 执行权限边界复杂化
3. 插件信任链条延长

攻击面扩展速度与安全治理机制完善速度之间存在阶段性差距。

# 三、互联网暴露面现状分析

## 3.1 全球暴露规模

根据 ZoomEye 测绘数据统计，截至2026年3月2日，全球可识别 OpenClaw 实例数量为 63,026 个。

![zoomeye_dork](./images/zoomeye_dork.png)

从地区分布来看，中国、美国、新加坡等国家的部署量位居前列，其中中国的部署规模显著高于美国，成为全球 OpenClaw 部署数量最多的国家。

![zoomeye_country](./images/zoomeye_country.png)

## 3.2 部署模式特征

识别到的典型部署模式包括：

* 默认端口映射部署
* 反向代理部署

其中默认端口映射部署为53,072个，占比85.41%，反向代理部署为4253个，占比6.75%。

![zoomeye_port](./images/zoomeye_port.png)

# 四、已披露安全漏洞

## 4.1 漏洞类型分布

截至2026年3月4日，GitHub Advisory Database 收录的漏洞多达245个。

![openclaw_vulns](./images/openclaw_vulns.png)

我们对收录的漏洞进行了汇总，详见：[openclaw_vulnerabilities.xlsx](openclaw_vulnerabilities.xlsx)

并对收录的漏洞进行统计分析，发现主要集中于以下类别：

### 1. 接口与认证访问控制问题

这是最频发的漏洞类型，涉及多个第三方集成平台（Telegram, Slack, Twilio 等）。

* **未授权 API 访问**：如 Telnyx webhook 缺失认证（CVE-2026-26319）和 Discord 鉴权缺陷。
* **认证与校验逻辑缺陷**：包括 BlueBubbles、Twilio 的 Webhook 认证绕过，以及多项 Allowlist（白名单）绕过漏洞（如 iMessage, Matrix, Voice-call）。
* **请求伪造 (SSRF/CSRF)**：共计 7 处 SSRF 漏洞，主要集中在 Gateway、Image 工具及 Cron Webhook 中，反映了对外部 URL 请求缺乏严格过滤。

### 2. 执行权限与沙箱边界问题

作为具备执行能力的 Agent，OpenClaw 在处理系统级命令时存在显著风险。

* **高危命令注入**：存在多处 RCE 和命令注入漏洞，如 Docker PATH 注入（CVE-2026-24763）和 sshNodeCommand 注入。
* **沙箱逃逸与权限提升**：最严重的漏洞为 CVSS 9.9 的 safeBins 验证绕过（CVE-2026-28363），可直接导致沙箱逃逸。此外还包括 Docker 容器逃逸及 ACP 自动批准绕过。
* **文件系统访问范围过宽**：涉及多项目录遍历与 LFI（本地文件包含）漏洞，如 Feishu 文件泄露和浏览器上传路径遍历。

### 3. 插件与自动化任务风险

AI Agent 通过“技能（Skills）”扩展能力，这引入了动态执行带来的安全隐患。

* **脚本与环境注入**：clawtributors 脚本注入（CVE-2026-26323）以及 Skill 环境变量覆盖注入。
* **下载与路径校验失效**：技能下载目录未经过有效验证（CVE-2026-27008），可能导致恶意插件植入。

### 4. 信息泄露与默认配置风险

* **敏感凭据暴露**：Telegram bot token 在日志中泄露（CVE-2026-27003），以及 skills.status 泄露密钥。
* **配置逻辑缺陷**：如 Sandbox 配置 Hash 问题及 macOS deep link 截断导致的逻辑错误。
* **UI 安全隐患**：Control UI 中存在多处存储型 XSS，可能影响管理员账户安全。

整体来看，这些漏洞反映出在 OpenClaw 高权限 AI Agent 系统中，对外部输入、执行环境以及插件生态的安全边界控制仍然不足。

## 4.2 高风险漏洞

### 1. Gateway反向代理认证绕过

2026年1月25日，Twitter 用户 theonejvo 发现 OpenClaw 在 Nginx 反向代理场景下存在未经授权的漏洞。OpenClaw 默认允许"本地连接"，因此当部署在 Nginx/Caddy 等反向代理服务器上时，所有请求都显示为来自后端 127.0.0.1。这样一来，它就被视为可信的本地连接。然而，如果trustedProxies配置不正确或启用了强制认证，任何用户都可以直接访问控制界面，该界面拥有代理配置、凭证存储、对话历史记录和命令执行等高权限。最终，该漏洞演变为对AI代理的完全控制。

![unauthorized_access_to_configuration](./images/unauthorized_access_to_configuration.png)

### 2. 1 Click 修改网关地址 RCE（CVE-2026-25253）

2026 年 2 月 1 日，安全公司 DepthFirst 发布博客公开 OpenClaw 的一个高危漏洞，该漏洞允许任意修改网关地址。App-settings.ts 会直接接收 gatewayUrl 中的查询参数并将其保存到本地存储。一旦设置新的网关，应用立即尝试建立连接，并在握手过程中将 authToken 发送至该网关。攻击者可利用这一流程构建完整攻击链：受害者在不知情的情况下点击精心设计的钓鱼链接，攻击者即可从窃取令牌开始，通过 WebSocket 连接访问本地端口 18789，最终实现任意命令执行。

![1_click_get_gateway_token](./images/1_click_get_gateway_token.png)

### 3. ClawJacked WebSocket 暴力破解（CVE-2026-25593）

2026年2月26日，安全公司 Oasis Security 披露了一个名为 ClawJacked 的高危漏洞，该漏洞是由于 OpenClaw 网关服务默认绑定本地主机，暴露了 WebSocket 接口。由于浏览器的跨源策略不会阻止 WebSocket 连接到 localhost，OpenClaw 用户访问的恶意网站可以利用 JavaScript 无声地打开与本地网关的连接并尝试认证，**而不会触发任何警告**。研究人员发现，他们可以以每秒数百次的暴力破解 OpenClaw 管理密码，**而不会限制或记录失败的尝试。**一旦猜测出正确密码，攻击者可以悄无声息地注册为可信设备，因为网关会自动批准本地主机的设备配对，无需用户确认。

![clawjacked](./images/clawjacked.png)

# 五、公开安全事件

### 5.1 邮件分析间接提示词注入

2026年1月27日，X 平台用户 Matvey Kukuy 发帖警告 OpenClaw 及其自动化邮件代理存在提示词注入风险。攻击者只需向机器人发送包含恶意指令的邮件，并诱导其主动读取邮件内容，邮件中的提示词即可被当作系统指令执行，从而操控代理访问本地或远程资源并回传敏感信息。在其演示中，机器人被诱导读取攻击邮件后，从受控机器中提取并返回私钥等敏感数据，整个攻击过程仅需数分钟即可完成。该案例表明，当智能体能够自动访问邮箱、文件或系统资源时，一旦缺乏对外部输入的隔离与校验，提示词注入可能被利用为远程控制入口，导致敏感数据泄露甚至主机被完全接管。

![email_prompt_injection](./images/email_prompt_injection.png)

### 5.2 插件市场分发恶意技能窃取数据

2026年2月1日，安全研究公司 Koi Security 研究员 Oren Yomtov 发现 OpenClaw 官方插件市场 ClawHub 中存在341个恶意 skill，并将该恶意攻击命名为：ClawHavoc。这些 skill 伪装成常用工具，下载包含macOS/Windows 木马的加密压缩包，如 Atomic macOS Stealer 等，一旦激活即可窃取用户邮箱、登录Token和API密钥等敏感数据。该事件表明 skill 带来新的技术范式，如果不加以严格审核和控制，拥有高权限的智能体往往会成为一把双刃剑，成为黑客攻击的跳板。

![clawhavoc](./images/clawhavoc.png)

### 5.3 Moltbook 社区数据库暴露导致智能体接管风险

2026年2月2日，安全公司Wiz 披露，OpenClaw 生态中的 Moltbook 安全社区存在严重数据库配置错误：平台使用的 Supabase 数据库未启用行级访问控制（RLS），且公开 API Key 被赋予全表读写权限，导致数据库几乎完全对外开放。攻击者只需使用该 API Key 即可直接访问和修改平台数据。

该漏洞导致约 150 万组 API 与认证令牌、3.5 万用户邮箱、登录令牌以及私信内容被暴露。更严重的是，攻击者可以利用泄露的认证信息 接管平台上的 AI 智能体账号，甚至冒用拥有大量粉丝的智能体发布内容或执行任务。

这一事件暴露出 OpenClaw 生态在 平台访问控制与密钥权限管理方面的严重缺陷。由于智能体具备自动发布与任务执行能力，一旦账号被劫持，攻击者便可能在任务链中植入恶意指令，从而进一步触发自动化攻击或恶意操作，形成对整个平台智能体生态的控制风险。

![moltbook_supabase](./images/moltbook_supabase.png)

### 5.4 网页抓取间接提示词注入

**2026年2月3日**，安全研究机构 HiddenLayer 的研究人员发布报告，详细披露了 OpenClaw 在网页抓取模式下存在的间接提示词注入（Indirect Prompt Injection）风险。攻击者通过在网页、文档或 HTML 源码中植入隐蔽的恶意指令（如隐藏在 <think> 标签或透明文本中），诱导正在总结网页内容的 OpenClaw 代理背离原始任务。在实际攻击演示中，这些指令通过篡改智能体的核心配置文件 SOUL.md，为攻击者建立了一个持久化的“AI 后门”。被劫持的智能体会静默地将用户的会话数据、API 令牌及私钥回传至攻击者的服务器。该事件揭示了 AI 智能体在处理外部非受信数据时，若缺乏对“数据”与“指令”的物理隔离，其自动化处理能力将直接被转化为攻击者的远程控制入口。

![web_fetch_injection](./images/web_fetch_injection.png)

### 5.5 误删 Meta 安全总监邮箱邮件

2026年2月23日，Meta 超级智能团队安全总监 Summer Yue 使用 OpenClaw 智能体清理个人邮箱时遭遇代理失控：AI 忽视"等待确认"指令，自行开始批量删除邮件。她紧急返回设备强制终止前，该代理已删除了200余封邮件。该事件暴露了智能体操作控制的失效，全面依赖模型判断，而不是在执行敏感操作时的硬性阻断机制。

![delete_email](./images/delete_email.png)

# 六、总结

随着 AI Agent 技术的快速发展，OpenClaw 作为开源智能体框架的代表，展示了高度自动化的任务执行与广泛的资源访问能力。然而，其高权限特性同时带来了复杂而多层次的安全风险。本文通过对 OpenClaw 项目的架构演进、互联网暴露面、已披露漏洞及公开安全事件的系统分析，揭示了以下关键问题：

1. **访问控制与权限管理缺陷**
    多数漏洞集中于接口认证失效、API 权限过大以及执行层沙箱边界松散，导致攻击者可直接利用未授权接口获取敏感数据或控制智能体。
2. **插件与自动化任务风险**
    第三方技能扩展和自动化任务链为智能体提供了灵活能力，但插件下载目录验证缺失、环境变量覆盖及脚本注入等漏洞，使智能体易成为攻击载体。
3. **信息泄露与配置失误**
    数据库未启用 RLS、日志中敏感凭据暴露、默认配置不安全等问题导致用户邮箱、API Key、登录令牌及私信信息大规模泄露，攻击者可接管智能体账号并植入恶意任务链。
4. **智能体自主执行控制不足**
    实际事件显示，当 AI 智能体完全依赖模型判断而缺乏硬性操作阻断时，可能出现误操作或被远程利用，如邮件批量删除事件及提示词注入攻击案例。

综上，OpenClaw 的安全事件与漏洞反映出 AI Agent 系统中，功能快速迭代与安全治理滞后之间的矛盾。未来需要在**访问控制、执行权限隔离、插件审计以及自动化任务安全机制**上建立更严格的安全策略，以保障智能体在真实生产环境中的可控性和可信度。

# 七、参考

1. OpenClaw ZoomEye 搜索链接：https://www.zoomeye.org/searchResult?q=YXBwPSJPcGVuQ2xhdyI%3D
2. Gateway反向代理认证绕过：https://x.com/theonejvo/status/2015401219746128322
3. 1 Click 修改网关地址 RCE（CVE-2026-25253）：https://depthfirst.com/post/1-click-rce-to-steal-your-moltbot-data-and-keys
4. ClawJacked WebSocket 暴力破解（CVE-2026-25593）：https://www.oasis.security/blog/openclaw-vulnerability
5. 邮件分析间接提示词注入：https://x.com/Mkukkk/status/2015951362270310879
6. 插件市场分发恶意技能窃取数据：https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting
7. Moltbook 社区数据库暴露导致智能体接管风险：https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys
8. 网页抓取间接提示词注入：https://www.hiddenlayer.com/research/exploring-the-security-risks-of-ai-assistants-like-openclaw
9. 误删 Meta 安全总监邮箱邮件：https://x.com/summeryue0/status/2025774069124399363
