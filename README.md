[**中文版**](README_zh-CN.md) | English

# Project Overview

OpenClaw is a powerful AI assistant that can run on your own hardware. First released in November 2025, it has released dozens of versions as of March 2026. While powerful, it also comes with significant security risks. According to ZoomEye mapping data, as of March 4, 2026, there are 63,026 identifiable OpenClaw instances worldwide, and the GitHub Advisory Database has recorded as many as 245 related vulnerabilities, highlighting the coexistence of rapid growth and security challenges. For some research findings on its security, [click here](docs/OpenClaw_Security_Analysis_2026.md) to view.

This project is an internal team summary of OpenClaw's full-lifecycle security practice guide, covering installation, configuration, daily use, and maintenance, helping you maintain security while enjoying OpenClaw's powerful capabilities.

# Quick Start

The audit script supports Linux, macOS, and Windows.

## Step 1: Assess Current Environment Security

Run the automated audit script to quickly check the security status of your OpenClaw environment:

```bash
git clone https://github.com/knownsec/openclaw-security.git
cd openclaw-security
python3 tools/openclaw_security_audit.py

# View the audit report
cat /tmp/openclaw-security-reports/report-$(date +%Y-%m-%d).txt
```

## Step 2: Strengthen OpenClaw Configuration

Copy the contents of `OpenClaw-Security-Practices-Guide.md` into the OpenClaw dialog so the AI assistant is aware of security practices and follows security best practices in future interactions.

## Step 3: Learn Daily Security Tips

Read through this README to master OpenClaw security practices across the entire lifecycle, including installation, configuration, daily use, incident response, and more.

# Security Guide
## Installing OpenClaw Securely

1. **Download OpenClaw from a trusted source**, official website: https://openclaw.ai. Some unofficial "quick deployment" or "one-click installation" scripts online may contain modified versions or backdoors.

2. Prioritize isolated environments. Do not use your primary computer system or sensitive machines. Recommended priority: Independent VPS > Local virtual machine (VMware, VirtualBox, etc.) > Local Docker.

3. Follow the principle of least privilege. Do not run or install OpenClaw using a root account or an account with administrator privileges. Incorrect example:

```bash
# Linux/macOS
curl -fsSL https://openclaw.ai/install.sh | sudo bash # Using sudo for convenience
```

Windows users:

```
Right-click "Command Prompt" and select "Run as administrator"
```

After installation, it is strongly recommended to copy the contents of `OpenClaw-Security-Practices-Guide.md` into the OpenClaw dialog.

4. **Upgrade to the latest version regularly**, do not use outdated versions:

```bash
openclaw update
```

5. Before any operation that may cause abnormal configuration, back up the critical OpenClaw data directory in advance:

```bash
# Linux/macOS
cp -a ~/.openclaw ~/openclaw_bak
```

Windows users:

```
Copy folder %USERPROFILE%\.openclaw to another location
```

## OpenClaw Configuration Check

The OpenClaw configuration file is located at `~/.openclaw/openclaw.json` (Linux/macOS) or `%USERPROFILE%\.openclaw\openclaw.json` (Windows).

1. **Minimize exposure**, run in local mode, do not expose port 18789 to the external network:

```bash
openclaw config set gateway.mode local
```

To prevent accidental operations, it is recommended to configure the system firewall to deny access to port 18789.

```bash
# Linux - Ubuntu ufw
sudo ufw enable
sudo ufw deny 18789/tcp
```

```
# macOS - System Preferences > Security & Privacy > Firewall
```

Windows users:

```
Control Panel > Windows Defender Firewall > Advanced Settings > Inbound Rules > New Rule
```

2. If providing access in an intranet environment, enable authentication and configure:

```bash
openclaw config set gateway.auth.mode token
openclaw config set gateway.auth.token <custom TOKEN>
```

## Using OpenClaw Securely

1. Regularly run OpenClaw security verification commands to check security configuration:

```bash
openclaw security audit --deep
```

2. SKILL Review
You must review SKILLs before installation, focusing on whether the SKILL exhibits the following behaviors:

- Arbitrary shell command execution
- File system writes (outside specified directories)
- Network requests to unknown domains
- Accessing environment variables/credentials
- Base64 encoded code
- Dynamic code execution (`eval`, `exec`)

Some common review points:

```bash
# Linux/macOS
grep -r "exec\|spawn\|child_process\|os.system\|subprocess" .
grep -r "fs.write\|fs.unlink\|rm \|chmod \|chown " .
grep -r "fetch\|axios\|requests\|http" .
grep -r "process.env\|\.env\|SECRET\|KEY\|TOKEN" .
```

Windows users:

```
Open search in SKILL directory, search for keywords: exec, spawn, SECRET, KEY, TOKEN, etc.
```

3. Sensitive operations, such as transactions and account logins, always require manual review.

4. Only enable necessary tools and disable unused ones promptly.

## Routine Checks

OpenClaw is very powerful but also brings many security risks. During daily use, you should regularly perform system checks.

1. Check if the Gateway port is bound to 0.0.0.0:

```bash
# Linux/macOS
ss -lntp | fgrep 18789
```

Windows users:

```
Open Command Prompt, type: netstat -ano | findstr 18789
```

2. For instances allowing remote access, directly visit http://<IP address>:18789 to verify whether anonymous access is allowed.

3. Check if the service is running with root identity:

```bash
# Linux/macOS
ps aux | grep openclaw | grep -v root
```

Windows users:

```
Task Manager > Details > Find openclaw process, check "User name"
```

4. Check if firewall access policies are configured:

```bash
# Linux - ufw
sudo ufw status | grep 18789
```

Windows users:

```
Control Panel > Windows Defender Firewall > Advanced Settings > Inbound Rules > Find 18789
```

## Incident Response

When system abnormalities are detected, such as lag, excessive traffic, or high CPU and memory usage:

1. Immediately stop the OpenClaw service

```bash
# Linux/macOS
killall openclaw-gateway
```

Windows users:

```
Task Manager > Find openclaw process > End task
```

2. Revoke all credentials

3. Check system logs:

```bash
# Linux/macOS
grep -E "auth_failed|unauthorized|error" /var/log/openclaw/*.log
```

Windows users:

```
Event Viewer > Windows Logs > Application/Security
```

4. Check system login accounts:

```bash
# Linux/macOS
w
```

Windows users:

```
Task Manager > Users tab
```

5. Check system processes:

```bash
# Linux/macOS
top
```

Windows users:

```
Task Manager
```

## Disaster Recovery and Backup

1. Regularly back up OpenClaw configuration and workspace:

```bash
# Linux/macOS
cp -r ~/.openclaw ~/openclaw-backup-$(date +%Y%m%d)
```

Windows users:

```
Copy folder %USERPROFILE%\.openclaw
```

2. Back up the list of installed SKILLs:

```bash
openclaw skill list > ~/skill-list-backup.txt
```

3. Recommend using Git to manage important workspaces for quick rollback in case of anomalies.

## Automated Security Audit

This project provides automated audit scripts that can execute most of the above checks with one command:

```bash
# Basic audit
python3 tools/openclaw_security_audit.py
ls /tmp/openclaw-security-reports/
```

Audit content includes:
- Environment isolation detection
- Port exposure check (18789)
- Permission compliance check
- SKILL source verification
- Sensitive information scanning (private keys, mnemonics, etc.)
- File integrity verification
- Process and network listening analysis
- System log audit

**It is recommended to add this script to your daily inspection routine and run audits regularly to continuously maintain OpenClaw security.**

# More References

Here are some additional references for more advanced users:

- [OpenClaw Official Documentation - Security](https://docs.openclaw.ai/gateway/security)

- [OpenClaw Security Practice Guide](https://github.com/slowmist/openclaw-security-practice-guide)

- [OpenClaw Security Guide](https://openclawsecurity.org/)
