# 项目介绍

OpenClaw 是一个可以运行在自己硬件上的强大的 AI 助手，于 2025 年 11 月首次发布，截至 2026 年 3 月已发布数十个版本。强大的同时也存在非常多的安全隐患，根据 ZoomEye 测绘数据，截至 2026 年 3 月 2 日，全球可识别的 OpenClaw 实例数量高达 63,026 个，GitHub Advisory Database 已收录相关漏洞多达 245 个，凸显其高速增长与安全挑战并存的现状，关于它的一些安全研究成果，[点击这里](docs/OpenClaw_Security_Analysis_2026_zh-CN.md)查看。

本项目是团队内部总结的 OpenClaw 全生命周期的安全实践指南，覆盖从安装、配置、日常使用、日常维护，助你在享受 OpenClaw 强大能力的同时守住安全底线。

目前本文档主要针对 Linux/macOS，Windows 尽请期待。

# 安全指南
## 安全地安装 OpenClaw

1. **从可信的地址下载 OpenClaw**，官网：https://openclaw.ai ，网上有些非官方提供的“快速部署”、“一键安装”可能包含修改版或后门。

2. 优先选择隔离环境，不要使用主力电脑系统或涉敏的计算机，推荐优先级：独立 VPS > 本地虚拟机（VMware、VirtualBox 等）、本地 Docker。

3. 最小权限原则，不要用 root 或具备管理员身份的账户运行及安装 OpenClaw，错误示例：

```bash
curl -fsSL https://openclaw.ai/install.sh | sudo bash # 为了图省事，用 sudo 安装
```

安装完毕以后，强烈建议将“OpenClaw安全实践指南.md”复制到 OpenClaw 对话框中。

4. **定期升级到最新版**，不要使用老版本：

```bash
openclaw update
```

5. 在任何可能会导致当前正常配置出现异常的情形下，请先提前备份好关键的 OpenClaw 数据目录：

```bash
cp -a ~/.openclaw ~/openclaw_bak
```

## OpenClaw 配置检查

OpenClaw 配置文件位于 ~/.openclaw/openclaw.json。

1. **最小化暴露**，以本地模式运行，不要将 18789 端口暴露在外网：

```bash
openclaw config set gateway.mode local
```

为了防止误操作，推荐给系统防火墙配置 18789 端口禁止访问的策略。示例：Ubuntu 自带的 ufw：

```bash
sudo ufw enable # 启动防火墙
sudo ufw deny 18789/tcp
```

2. 若是在内网环境中提供访问，启用认证，配置：

```bash
openclaw config set gateway.auth.mode token
openclaw config set gateway.auth.token <自定义 TOKEN>
```

## 安全地使用 OpenClaw

1. 定期执行 OpenClaw 安全验证命令检查安全配置：

```bash
openclaw security audit --deep
```

2. SKILL 审查
安装 SKILL 前必须审查，关注 SKILL 是否存在以下行为：

- 任意 shell 命令执行
- 文件系统写入（除指定目录外）
- 网络请求到未知域名
- 访问环境变量/凭证
- Base64 编码的代码
- 动态代码执行 (`eval`, `exec`)

一些常见的审查点：

```bash
grep -r "exec\|spawn\|child_process\|os.system\|subprocess" .
grep -r "fs.write\|fs.unlink\|rm \|chmod \|chown " .
grep -r "fetch\|axios\|requests\|http" .
grep -r "process.env\|\.env\|SECRET\|KEY\|TOKEN" .
```

3. 涉及敏感的操作，如交易、登录账号等一律需要人工审核。

4. 只开启必要的 tools，不使用的及时禁用。

## 日常检查
OpenClaw 非常强大，同时也带来很多安全风险，在日常使用过程中应当经常对系统做一些检查。

1. 检查 Gateway 的端口是否绑定在 0.0.0.0：

```bash
ss -lntp | fgrep 18789
```

2. 对于允许远程访问的，请直接访问 http://<IP地址>:18789，核实是否允许匿名访问。

3. 检查是否用 root 身份运行服务：

```bash
ps aux | grep openclaw | grep -v root
```

4. 检查是否配置防火墙访问策略，以 ufw 为例：

```bash
sudo ufw status | grep 18789
```

## 应急响应

当发现系统出现异常时，如卡顿、流量过大、CPU及内存占用率过高时：

1. 立即停止 OpenClaw 服务

2. 吊销所有凭证

3. 检查系统日志，如：

```bash
grep -E "auth_failed|unauthorized|error" /var/log/openclaw/*.log
```

4. 检查系统登录账号：

```bash
w
```

5. 检查系统进程：

```bash
top
```

## 灾备与恢复

1. 定期备份 OpenClaw 配置和工作空间：

```bash
cp -r ~/.openclaw ~/openclaw-backup-$(date +%Y%m%d)
```

2. 备份已安装的 SKILL 列表：

```bash
openclaw skill list > ~/skill-list-backup.txt
```

3. 建议使用 Git 管理重要工作空间，发生异常时可快速回滚。

## 自动化安全审计

本项目提供自动化审计脚本，可一键执行上述大部分检查：

```bash
# 基础审计
python3 tools/openclaw_security_audit.py
# 审计报告保存位置
ls /tmp/openclaw-security-reports/
```

审计内容包括：
- 环境隔离检测
- 端口暴露检查（18789）
- 权限合规检查
- SKILL 来源验证
- 敏感信息扫描（私钥、助记词等）
- 文件完整性校验
- 进程和网络监听分析
- 系统日志审计

# 更多参考

这里有一些其他参考，面向需要个性化的用户：

- [OpenClaw 官方文档安全相关](https://docs.openclaw.ai/gateway/security)

- [OpenClaw Security Practice Guide](https://github.com/slowmist/openclaw-security-practice-guide)

- [OpenClaw Security Guide](https://openclawsecurity.org/)
