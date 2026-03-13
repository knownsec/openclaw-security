#!/usr/bin/env python3

import os
import sys
import json
import csv
import re
import hashlib
import subprocess
import datetime
import locale
import platform
from pathlib import Path
from typing import List, Tuple, Dict, Optional

IS_WINDOWS = sys.platform == 'win32'
IS_MACOS = sys.platform == 'darwin'
IS_LINUX = sys.platform.startswith('linux')

OC_STATE_DIR = Path(os.environ.get(
    'OPENCLAW_STATE_DIR',
    Path.home() / '.openclaw'
))

# Platform-specific report directory
if IS_WINDOWS:
    REPORT_DIR = Path(os.environ.get('TEMP', '/tmp')) / 'openclaw-security-reports'
else:
    REPORT_DIR = Path('/tmp/openclaw-security-reports')

DATE_STR = datetime.date.today().isoformat()
REPORT_FILE = REPORT_DIR / f'report-{DATE_STR}.txt'

# ANSI color codes
RED = '\033[91m'
RESET = '\033[0m'


def is_chinese_locale() -> bool:
    try:
        lang = os.environ.get('LANG', '').lower()
        lc_all = os.environ.get('LC_ALL', '').lower()
        lc_ctype = os.environ.get('LC_CTYPE', '').lower()

        for var in [lang, lc_all, lc_ctype]:
            if 'zh' in var or 'cn' in var:
                return True

        loc = locale.getlocale()[0]
        if loc and ('zh' in loc.lower() or 'cn' in loc.lower()):
            return True

        return False
    except Exception:
        return False


USE_ZH = is_chinese_locale()

I18N = {
    'zh': {
        'audit_result_class_doc': '审计结果类',
        'add_success_doc': '添加成功信息',
        'add_warning_doc': '添加警告信息',
        'get_summary_doc': '获取汇总信息',
        'ok': 'OK',
        'warning': '警告',
        'daily_brief_title': 'OpenClaw 每日安全巡检简报',
        'warning_items': '警告项目：',
        'run_command_doc': '执行命令并返回结果',
        'run_command_args_doc': '命令列表',
        'run_command_capture': '是否捕获输出',
        'run_command_check': '是否检查返回码',
        'run_command_returns': '(返回码, 标准输出, 标准错误)',
        'command_not_found': '命令未找到',
        'write_report_doc': '写入报告文件',
        'append_report_doc': '追加内容到报告文件',
        'platform_audit_header': 'OpenClaw 基础审计 (--deep)',
        'platform_audit_success': '平台审计: 已执行原生扫描',
        'platform_audit_failed': '平台审计: 执行失败（详见详细报告）',
        'isolation_check_header': '运行环境隔离性检测',
        'detected_docker': '检测到 Docker 容器环境',
        'detected_container_cgroup': '检测到容器环境 (cgroup)',
        'detected_vm': '检测到虚拟机环境 ({})',
        'virt_type': '虚拟化类型: {}',
        'env_isolated': '环境隔离: 运行在隔离环境中',
        'no_vm_detected': '未检测到虚拟机/容器环境特征',
        'env_not_isolated': '环境隔离: 建议在隔离环境 (VM/Docker) 中运行 OpenClaw',
        'privilege_check_header': '最小权限原则检测',
        'running_as_root': '当前以 root 身份运行',
        'running_as_user': '当前以普通用户运行',
        'root_warning': '权限检查: 不建议以 root 身份运行 OpenClaw',
        'privilege_ok': '权限检查: 符合最小权限原则',
        'gateway_exposure_header': 'Gateway 端口 (18789) 暴露检测',
        'listening_record': '监听记录: {}',
        'listening_all': '监听所有接口 (0.0.0.0/::)',
        'listening_local': '仅监听本地 (127.0.0.1/::1)',
        'port_exposed_warning': '端口暴露: 18789 端口监听所有接口，建议绑定 127.0.0.1',
        'port_local_ok': '端口暴露: 18789 端口仅本地监听',
        'port_not_listening': '未检测到 18789 端口监听',
        'gateway_not_running': '端口暴露: Gateway 未运行或端口未监听',
        'skill_trust_header': 'Skill 可信来源检测',
        'skills_dir_not_found': '未找到 skills 目录',
        'no_skills_installed': 'Skill 信任: 无已安装技能',
        'skill_total': '总计: {} 个技能 (Git来源: {}, 本地: {})',
        'skill_git_source': '  [{}] {}',
        'too_many_skills': 'Skill 信任: 已安装 {} 个技能，建议定期审查',
        'skills_count': 'Skill 信任: 已安装 {} 个技能',
        'version_info_header': 'OpenClaw 版本信息',
        'current_version': '当前版本: {}',
        'latest_version': '最新版本: {}',
        'version_not_latest': '版本检查: 当前版本 {} 非最新版本，建议升级',
        'version_ok': '版本检查: 当前版本 {}',
        'process_network_header': '监听端口与高资源进程',
        'ss_failed': 'ss 命令执行失败',
        'process_network_ok': '进程网络: 已采集监听端口与进程快照',
        'sensitive_dirs_header': '敏感目录近 24h 变更文件数',
        'total_modified_files': '总计变更文件数: {}',
        'dir_changes': '目录变更: {} 个文件 (位于 /etc/ 或 ~/.ssh 等)',
        'system_cron_header': '系统级定时任务与 Systemd Timers',
        'systemctl_failed': 'systemctl 命令执行失败',
        'system_cron_ok': '系统 Cron: 已采集系统级定时任务信息',
        'openclaw_cron_header': 'OpenClaw Cron Jobs',
        'no_openclaw_cron': '未找到 openclaw cron 命令',
        'local_cron_ok': '本地 Cron: 已拉取内部任务列表',
        'local_cron_failed': '本地 Cron: 拉取失败（可能是 token/权限问题）',
        'ssh_header': '最近登录记录与 SSH 失败尝试',
        'last_failed': 'last 命令执行失败',
        'ssh_failed_attempts': 'SSH 失败尝试 (近24h): {}',
        'ssh_security_ok': 'SSH 安全: 近24h 失败尝试 {} 次',
        'file_integrity_header': '关键配置文件权限与哈希基线',
        'baseline_not_exist': '基线文件不存在',
        'file_not_exist': '文件不存在: {}',
        'hash_mismatch': '哈希不匹配: {}',
        'hash_ok': 'OK',
        'hash_check': '哈希校验: {}',
        'permissions': '权限: {}',
        'baseline_ok': '配置基线: 哈希校验通过且权限合规',
        'baseline_warning': '配置基线: 基线缺失/校验异常或权限不合规',
        'yellow_line_header': '黄线操作对比 (sudo logs vs memory)',
        'sudo_log': 'Sudo 日志: {}, Memory 日志: {}',
        'yellow_line_ok': '黄线审计: sudo记录={}, memory记录={}',
        'disk_usage_header': '磁盘使用率与最近大文件',
        'disk_usage': '磁盘使用: {}, 大文件 (>100M): {}',
        'disk_capacity': '磁盘容量: 根分区占用 {}, 新增 {} 个大文件',
        'env_variables_header': 'Gateway 环境变量泄露扫描',
        'sensitive_vars_found': '发现敏感环境变量: ',
        'no_sensitive_vars': '未发现明显的敏感变量名',
        'env_var_hidden': '{}=(已隐藏)',
        'env_scan_ok': '环境变量: 已执行网关进程敏感变量名扫描',
        'env_cannot_read': '环境变量: 无法读取进程环境文件',
        'env_no_process': '环境变量: 未定位到 openclaw-gateway 进程',
        'dlp_header': '明文私钥/助记词泄露扫描 (DLP)',
        'dlp_result': 'DLP 扫描结果: {}',
        'dlp_found': '敏感凭证扫描: 检测到疑似明文敏感信息({})，请人工复核',
        'dlp_ok': '敏感凭证扫描: 未发现明显私钥/助记词模式',
        'skill_integrity_header': 'Skill/MCP 完整性基线对比',
        'changes_detected': '检测到变化:\n',
        'integrity_changed': 'Skill/MCP基线: 检测到文件哈希变化（详见diff）',
        'integrity_ok': 'Skill/MCP基线: 与上次基线一致',
        'integrity_first': 'Skill/MCP基线: 首次生成基线完成',
        'integrity_no_files': 'Skill/MCP基线: 未发现 skills/mcp 目录文件',
        'disaster_recovery_header': '大脑灾备 (Git Backup)',
        'no_git_repo': '灾备备份: 未初始化 Git 仓库，已跳过',
        'no_changes': '无新变更，跳过提交',
        'backup_failed': '推送失败: {}',
        'backup_error': '备份过程出错: {}',
        'backup_ok': '灾备备份: 已自动推送至远端仓库',
        'backup_skip': '灾备备份: 无新变更，跳过推送',
        'backup_push_failed': '灾备备份: 推送失败（不影响本次巡检）',
        'telegram_send_failed': 'Telegram 发送失败: {}',
        'report_title': '=== OpenClaw 安全审计详细报告 ({}) ===',
        'version_unknown': '未知',
        'detailed_report_saved': '详细报告已保存至: {}',
        'new_addition': '新增: {}',
        'modified': '变更: {}',
        'disk_unknown': '未知',
        'vuln_check_header': '已知漏洞版本匹配',
        'vuln_csv_not_found': '漏洞数据库文件未找到: {}',
        'vuln_version_unknown': '漏洞检查: 无法获取当前 OpenClaw 版本号',
        'vuln_none_matched': '漏洞检查: 当前版本 {} 未命中已知漏洞 (检查 {} 个 CVE/GHSA)',
        'vuln_matched': '漏洞检查: 当前版本 {} 命中 {} 个已知漏洞 ({} Critical, {} High, {} Moderate, {} Low)',
        'vuln_detail': '  [{severity}] {id} - {title}',
        'vuln_affected': '    影响版本: {affected}',
        'vuln_link': '    详情: {link}',
    },
    'en': {
        'audit_result_class_doc': 'Audit result class',
        'add_success_doc': 'Add success message',
        'add_warning_doc': 'Add warning message',
        'get_summary_doc': 'Get summary',
        'ok': 'OK',
        'warning': 'WARNING',
        'daily_brief_title': 'OpenClaw Daily Security Brief',
        'warning_items': 'Warning Items:',
        'run_command_doc': 'Execute command and return result',
        'run_command_args_doc': 'Command list',
        'run_command_capture': 'Whether to capture output',
        'run_command_check': 'Whether to check return code',
        'run_command_returns': '(return code, stdout, stderr)',
        'command_not_found': 'Command not found',
        'write_report_doc': 'Write report file',
        'append_report_doc': 'Append content to report file',
        'platform_audit_header': 'OpenClaw Basic Audit (--deep)',
        'platform_audit_success': 'Platform Audit: Native scan executed',
        'platform_audit_failed': 'Platform Audit: Execution failed (see detailed report)',
        'isolation_check_header': 'Runtime Environment Isolation Check',
        'detected_docker': 'Detected Docker container environment',
        'detected_container_cgroup': 'Detected container environment (cgroup)',
        'detected_vm': 'Detected VM environment ({})',
        'virt_type': 'Virtualization type: {}',
        'env_isolated': 'Environment Isolation: Running in isolated environment',
        'no_vm_detected': 'No VM/container environment detected',
        'env_not_isolated': 'Environment Isolation: Recommend running OpenClaw in isolated environment (VM/Docker)',
        'privilege_check_header': 'Least Privilege Principle Check',
        'running_as_root': 'Currently running as root',
        'running_as_user': 'Currently running as normal user',
        'root_warning': 'Privilege Check: Not recommended to run OpenClaw as root',
        'privilege_ok': 'Privilege Check: Complies with least privilege principle',
        'gateway_exposure_header': 'Gateway Port (18789) Exposure Check',
        'listening_record': 'Listening record: {}',
        'listening_all': 'Listening on all interfaces (0.0.0.0/::)',
        'listening_local': 'Listening only on localhost (127.0.0.1/::1)',
        'port_exposed_warning': 'Port Exposure: Port 18789 listening on all interfaces, recommend binding to 127.0.0.1',
        'port_local_ok': 'Port Exposure: Port 18789 listening only on localhost',
        'port_not_listening': 'Port 18789 not detected listening',
        'gateway_not_running': 'Port Exposure: Gateway not running or port not listening',
        'skill_trust_header': 'Skill Trust Source Check',
        'skills_dir_not_found': 'Skills directory not found',
        'no_skills_installed': 'Skill Trust: No skills installed',
        'skill_total': 'Total: {} skills (Git source: {}, Local: {})',
        'skill_git_source': '  [{}] {}',
        'too_many_skills': 'Skill Trust: {} skills installed, recommend regular review',
        'skills_count': 'Skill Trust: {} skills installed',
        'version_info_header': 'OpenClaw Version Info',
        'current_version': 'Current version: {}',
        'latest_version': 'Latest version: {}',
        'version_not_latest': 'Version Check: Current version {} is not latest, recommend upgrade',
        'version_ok': 'Version Check: Current version {}',
        'process_network_header': 'Listening Ports and High Resource Processes',
        'ss_failed': 'ss command execution failed',
        'process_network_ok': 'Process Network: Collected listening ports and process snapshot',
        'sensitive_dirs_header': 'Sensitive Directory Changes in Last 24h',
        'total_modified_files': 'Total modified files: {}',
        'dir_changes': 'Directory Changes: {} files (in /etc/ or ~/.ssh, etc.)',
        'system_cron_header': 'System-level Cron Jobs and Systemd Timers',
        'systemctl_failed': 'systemctl command execution failed',
        'system_cron_ok': 'System Cron: Collected system-level cron job info',
        'openclaw_cron_header': 'OpenClaw Cron Jobs',
        'no_openclaw_cron': 'openclaw cron command not found',
        'local_cron_ok': 'Local Cron: Internal task list retrieved',
        'local_cron_failed': 'Local Cron: Retrieval failed (possible token/permission issue)',
        'ssh_header': 'Recent Login Records and SSH Failed Attempts',
        'last_failed': 'last command execution failed',
        'ssh_failed_attempts': 'SSH failed attempts (last 24h): {}',
        'ssh_security_ok': 'SSH Security: {} failed attempts in last 24h',
        'file_integrity_header': 'Key Config File Permissions and Hash Baseline',
        'baseline_not_exist': 'Baseline file does not exist',
        'file_not_exist': 'File does not exist: {}',
        'hash_mismatch': 'Hash mismatch: {}',
        'hash_ok': 'OK',
        'hash_check': 'Hash check: {}',
        'permissions': 'Permissions: {}',
        'baseline_ok': 'Config Baseline: Hash verification passed and permissions compliant',
        'baseline_warning': 'Config Baseline: Baseline missing/verification failed or permissions non-compliant',
        'yellow_line_header': 'Yellow Line Operations Comparison (sudo logs vs memory)',
        'sudo_log': 'Sudo logs: {}, Memory logs: {}',
        'yellow_line_ok': 'Yellow Line Audit: sudo records={}, memory records={}',
        'disk_usage_header': 'Disk Usage and Recent Large Files',
        'disk_usage': 'Disk usage: {}, Large files (>100M): {}',
        'disk_capacity': 'Disk Capacity: Root partition usage {}, {} new large files',
        'env_variables_header': 'Gateway Environment Variable Leakage Scan',
        'sensitive_vars_found': 'Found sensitive environment variables: ',
        'no_sensitive_vars': 'No obvious sensitive variable names found',
        'env_var_hidden': '{}=(hidden)',
        'env_scan_ok': 'Environment Variables: Scanned gateway process for sensitive variable names',
        'env_cannot_read': 'Environment Variables: Cannot read process environment file',
        'env_no_process': 'Environment Variables: openclaw-gateway process not found',
        'dlp_header': 'Plaintext Private Key/Mnemonic Leakage Scan (DLP)',
        'dlp_result': 'DLP scan result: {}',
        'dlp_found': 'Sensitive Credential Scan: Detected suspected plaintext sensitive info ({}), please manual review',
        'dlp_ok': 'Sensitive Credential Scan: No obvious private key/mnemonic patterns found',
        'skill_integrity_header': 'Skill/MCP Integrity Baseline Comparison',
        'changes_detected': 'Changes detected:\n',
        'integrity_changed': 'Skill/MCP Baseline: File hash changes detected (see diff for details)',
        'integrity_ok': 'Skill/MCP Baseline: Consistent with last baseline',
        'integrity_first': 'Skill/MCP Baseline: First baseline generation completed',
        'integrity_no_files': 'Skill/MCP Baseline: No skills/mcp directory files found',
        'disaster_recovery_header': 'Brain Disaster Recovery (Git Backup)',
        'no_git_repo': 'Disaster Recovery Backup: Git repository not initialized, skipped',
        'no_changes': 'No new changes, skipping commit',
        'backup_failed': 'Push failed: {}',
        'backup_error': 'Backup process error: {}',
        'backup_ok': 'Disaster Recovery Backup: Automatically pushed to remote repository',
        'backup_skip': 'Disaster Recovery Backup: No new changes, skipping push',
        'backup_push_failed': 'Disaster Recovery Backup: Push failed (does not affect this audit)',
        'telegram_send_failed': 'Telegram send failed: {}',
        'report_title': '=== OpenClaw Security Audit Detailed Report ({}) ===',
        'version_unknown': 'Unknown',
        'detailed_report_saved': 'Detailed report saved to: {}',
        'new_addition': 'New: {}',
        'modified': 'Modified: {}',
        'disk_unknown': 'Unknown',
        'vuln_check_header': 'Known Vulnerability Version Matching',
        'vuln_csv_not_found': 'Vulnerability database file not found: {}',
        'vuln_version_unknown': 'Vuln Check: Unable to determine current OpenClaw version',
        'vuln_none_matched': 'Vuln Check: Current version {} not affected by known vulnerabilities (checked {} CVE/GHSA)',
        'vuln_matched': 'Vuln Check: Current version {} matches {} known vulnerabilities ({} Critical, {} High, {} Moderate, {} Low)',
        'vuln_detail': '  [{severity}] {id} - {title}',
        'vuln_affected': '    Affected versions: {affected}',
        'vuln_link': '    Details: {link}',
    }
}


def t(key: str, *args, **kwargs) -> str:
    """Translation helper function"""
    lang = 'zh' if USE_ZH else 'en'
    template = I18N[lang].get(key, key)
    if kwargs:
        return template.format(**kwargs)
    return template.format(*args) if args else template


class AuditResult:
    def __init__(self):
        self.summary_lines = []
        self.warnings = []

    def add_success(self, message: str):
        self.summary_lines.append(f"[{t('ok')}] {message}")

    def add_warning(self, message: str):
        warn_msg = f"{RED}[{t('warning')}] {message}{RESET}"
        self.warnings.append(warn_msg)
        self.summary_lines.append(warn_msg)

    def get_summary(self) -> str:
        lines = [f"{t('daily_brief_title')} ({DATE_STR})", ""]
        lines.extend(self.summary_lines)
        if self.warnings:
            lines.append("")
            lines.append(f"{RED}{t('warning_items')}{RESET}")
            lines.extend(self.warnings)
        return "\n".join(lines)


def run_command(
    cmd: List[str],
    capture: bool = True,
    check: bool = False,
    shell: bool = False
) -> Tuple[int, str, str]:
    try:
        # Windows requires shell=True for some commands like PowerShell
        use_shell = shell or (IS_WINDOWS and len(cmd) > 0 and cmd[0].lower().endswith('powershell.exe'))
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=check,
            shell=use_shell
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr
    except FileNotFoundError:
        return -1, "", t('command_not_found')
    except Exception as e:
        return -1, "", str(e)


def setup_report_dir() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)


def write_report(content: str) -> None:
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(content)


def append_report(content: str) -> None:
    with open(REPORT_FILE, 'a', encoding='utf-8') as f:
        f.write(content)


def audit_platform(result: AuditResult) -> None:
    append_report(f"\n{t('platform_audit_header')}")
    code, stdout, stderr = run_command([
        'openclaw', 'security', 'audit', '--deep'
    ], check=False)

    append_report(stdout or stderr)

    if code == 0:
        result.add_success(t('platform_audit_success'))
    else:
        result.add_warning(t('platform_audit_failed'))


def audit_isolation(result: AuditResult) -> None:
    """Check runtime environment isolation"""
    append_report(f"\n{t('isolation_check_header')}")

    if IS_WINDOWS:
        isolation_info = []
        is_isolated = False

        # Check for WSL
        code, output, _ = run_command(['wsl.exe', '--list', '--quiet'], check=False)
        if code == 0 and output.strip():
            isolation_info.append("Detected WSL (Windows Subsystem for Linux)")
            is_isolated = True

        # Check for Hyper-V
        code, output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-ComputerInfo | Select-Object -ExpandProperty HyperVisorPresent'
        ], check=False)
        if 'True' in output:
            isolation_info.append("Detected Hyper-V")
            is_isolated = True

        # Check for Virtual Machine via wmic
        code, output, _ = run_command([
            'wmic', 'computersystem', 'get', 'model'
        ], check=False)
        if output and 'virtual' in output.lower():
            if 'Detected VM environment' not in str(isolation_info):
                isolation_info.append(f"Detected VM environment ({output.strip()})")
                is_isolated = True

        # Check for Docker Desktop
        code, output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-Service -Name Docker -ErrorAction SilentlyContinue'
        ], check=False)
        if code == 0 and output:
            isolation_info.append(t('detected_docker'))
            is_isolated = True

        if isolation_info:
            append_report(" | ".join(isolation_info))
            result.add_success(t('env_isolated'))
        else:
            append_report(t('no_vm_detected'))
            result.add_warning(t('env_not_isolated'))
        return

    if IS_MACOS:
        isolation_info = []
        is_isolated = False

        # Check for Docker
        docker_path = Path('/.dockerenv')
        if docker_path.exists():
            isolation_info.append(t('detected_docker'))
            is_isolated = True

        # Check hardware model for VM detection
        code, hw_model, _ = run_command([
            'sysctl', '-n', 'hw.model'
        ], check=False)
        if hw_model:
            vm_keywords = ['vmware', 'virtualbox', 'parallels', 'qemu']
            for keyword in vm_keywords:
                if keyword in hw_model.lower():
                    isolation_info.append(f"Detected VM environment ({hw_model.strip()})")
                    is_isolated = True
                    break

        # Check CPU brand string
        code, cpu_brand, _ = run_command([
            'sysctl', '-n', 'machdep.cpu.brand_string'
        ], check=False)
        if cpu_brand and 'qemu' in cpu_brand.lower():
            if 'Detected VM' not in str(isolation_info):
                isolation_info.append(f"Detected VM (QEMU)")
                is_isolated = True

        if isolation_info:
            append_report(" | ".join(isolation_info))
            result.add_success(t('env_isolated'))
        else:
            append_report(t('no_vm_detected'))
            result.add_warning(t('env_not_isolated'))
        return

    # Linux detection logic
    isolation_info = []
    is_isolated = False

    docker_path = Path('/.dockerenv')
    if docker_path.exists():
        isolation_info.append(t('detected_docker'))
        is_isolated = True

    _, cgroup_output, _ = run_command(['cat', '/proc/1/cgroup'], check=False)
    if cgroup_output and ('docker' in cgroup_output.lower() or 'kubepods' in cgroup_output.lower()):
        if t('detected_docker') not in isolation_info:
            isolation_info.append(t('detected_container_cgroup'))
            is_isolated = True

    _, dmi_output, _ = run_command(['cat', '/sys/class/dmi/id/product_name'], check=False)
    if dmi_output:
        vm_keywords = ['vmware', 'virtualbox', 'kvm', 'qemu', 'xen', 'hyper-v']
        for keyword in vm_keywords:
            if keyword in dmi_output.lower():
                isolation_info.append(t('detected_vm', dmi_output.strip()))
                is_isolated = True
                break

    code, virt_output, _ = run_command(['systemd-detect-virt'], check=False)
    if code == 0 and virt_output.strip() != 'none':
        if t('virt_type', virt_output.strip()) not in str(isolation_info):
            isolation_info.append(t('virt_type', virt_output.strip()))
            is_isolated = True

    if isolation_info:
        append_report(" | ".join(isolation_info))
        result.add_success(t('env_isolated'))
    else:
        append_report(t('no_vm_detected'))
        result.add_warning(t('env_not_isolated'))


def audit_root_privilege(result: AuditResult) -> None:
    append_report(f"\n{t('privilege_check_header')}")

    if IS_WINDOWS:
        # Check if openclaw-gateway process is running as Administrator
        code, pid_output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-Process openclaw-gateway -ErrorAction SilentlyContinue | ' +
            'Select-Object -ExpandProperty Id'
        ], check=False)

        if pid_output and pid_output.strip().isdigit():
            gw_pid = pid_output.strip()
            code, user_output, _ = run_command([
                'powershell.exe', '-Command',
                f'(Get-Process -Id {gw_pid} -ErrorAction SilentlyContinue).UserName'
            ], check=False)

            if user_output and 'administrator' in user_output.lower():
                append_report(f"OpenClaw Gateway running as: {user_output.strip()}")
                result.add_warning(t('root_warning'))
            else:
                append_report(f"OpenClaw Gateway running as: {user_output.strip() or 'normal user'}")
                result.add_success(t('privilege_ok'))
        else:
            append_report("OpenClaw Gateway process not found")
            result.add_success("OpenClaw Gateway 未运行")
        return

    # Linux: Check openclaw-gateway process user
    _, pgrep_output, _ = run_command([
        'pgrep', '-f', 'openclaw-gateway'
    ], check=False)

    if pgrep_output and pgrep_output.strip().isdigit():
        gw_pid = pgrep_output.strip()
        _, user_output, _ = run_command([
            'ps', '-o', 'user=', '-p', gw_pid
        ], check=False)

        if user_output:
            user = user_output.strip()
            if user == 'root':
                append_report(f"OpenClaw Gateway running as: {user}")
                result.add_warning(t('root_warning'))
            else:
                append_report(f"OpenClaw Gateway running as: {user}")
                result.add_success(t('privilege_ok'))
        else:
            append_report(t('running_as_user'))
            result.add_success(t('privilege_ok'))
    else:
        append_report("OpenClaw Gateway process not found")
        result.add_success("OpenClaw Gateway 未运行")


def audit_gateway_exposure(result: AuditResult) -> None:
    append_report(f"\n{t('gateway_exposure_header')}")

    exposed = False
    binding_info = []

    if IS_WINDOWS:
        # Use PowerShell to get listening ports on Windows
        code, output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-NetTCPConnection -LocalPort 18789 -State Listen -ErrorAction SilentlyContinue | ' +
            'Select-Object LocalAddress,OwningProcess | Format-Table -HideTableHeaders'
        ], check=False)

        if output and output.strip():
            for line in output.strip().split('\n'):
                if line.strip() and '18789' not in line:  # Header line
                    append_report(t('listening_record', line.strip()))
                    if '0.0.0.0' in line or '[::]' in line:
                        exposed = True
                        binding_info.append(t('listening_all'))
                    elif '127.0.0.1' in line or '[::1]' in line:
                        binding_info.append(t('listening_local'))
    elif IS_MACOS:
        # macOS: use lsof command
        _, lsof_output, _ = run_command([
            'lsof', '-i', ':18789', '-P', '-n'
        ], check=False)

        if lsof_output:
            for line in lsof_output.split('\n'):
                if 'LISTEN' in line and 'TCP' in line:
                    append_report(t('listening_record', line.strip()))
                    if '*:18789' in line or '0.0.0.0:18789' in line:
                        exposed = True
                        binding_info.append(t('listening_all'))
                    elif '127.0.0.1:18789' in line or '[::1]:18789' in line or 'localhost:18789' in line:
                        binding_info.append(t('listening_local'))
    else:
        # Linux: use ss command
        _, ss_output, _ = run_command([
            'ss', '-tunlp'
        ], check=False)

        if ss_output:
            for line in ss_output.split('\n'):
                if '18789' in line:
                    append_report(t('listening_record', line.strip()))
                    if '0.0.0.0:18789' in line or '[::]:18789' in line:
                        exposed = True
                        binding_info.append(t('listening_all'))
                    elif '127.0.0.1:18789' in line or '[::1]:18789' in line:
                        binding_info.append(t('listening_local'))

    if binding_info:
        append_report(" | ".join(binding_info))

    if exposed:
        result.add_warning(t('port_exposed_warning'))
    elif binding_info:
        result.add_success(t('port_local_ok'))
    else:
        append_report(t('port_not_listening'))
        result.add_success(t('gateway_not_running'))


def audit_skill_trust(result: AuditResult) -> None:
    append_report(f"\n{t('skill_trust_header')}")

    skill_dir = OC_STATE_DIR / 'workspace' / 'skills'

    if not skill_dir.exists():
        append_report(t('skills_dir_not_found'))
        result.add_success(t('no_skills_installed'))
        return

    # count skills and sources
    skill_count = 0
    from_git = 0
    from_local = 0
    unknown = 0

    for skill_path in skill_dir.iterdir():
        if skill_path.is_dir():
            skill_count += 1
            git_dir = skill_path / '.git'
            if git_dir.exists():
                from_git += 1
                code, remote_output, _ = run_command([
                    'git', '-C', str(skill_path),
                    'remote', '-v'
                ], check=False)
                if remote_output:
                    append_report(t('skill_git_source', skill_path.name, remote_output.split()[0] if remote_output.split() else 'unknown'))
            else:
                from_local += 1

    append_report(t('skill_total', skill_count, from_git, from_local))

    if skill_count > 10:
        result.add_warning(t('too_many_skills', skill_count))
    else:
        result.add_success(t('skills_count', skill_count))


def parse_version(ver_str: str) -> Tuple:
    """Parse a version string into a comparable tuple.

    Handles formats like: 2026.3.7, 2026.2.19-2, 2026.1.29-beta.1, v2026.1.29, 2.0.0-beta3
    Returns a tuple of (major, minor, patch, suffix_sort_key, suffix_value) for comparison.
    Non-numeric suffixes (beta/alpha/rc) sort before the same version's stable release.
    """
    ver_str = ver_str.strip().lstrip('v')
    suffix = None
    if '-' in ver_str:
        base, suffix = ver_str.split('-', 1)
    else:
        base = ver_str

    parts = []
    for p in base.split('.'):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)

    if suffix is None:
        return tuple(parts) + (1, 0)
    try:
        return tuple(parts) + (1, int(suffix))
    except ValueError:
        # beta, alpha, rc etc. sort before stable (suffix_sort_key=0)
        m = re.search(r'(\d+)', suffix)
        suffix_num = int(m.group(1)) if m else 0
        return tuple(parts) + (0, suffix_num)


def check_version_condition(current: Tuple, condition: str) -> bool:
    """Check if current version satisfies a single condition like '<= 2026.3.7'."""
    condition = condition.strip()
    if not condition:
        return False

    ops = [('<=', lambda a, b: a <= b),
           ('>=', lambda a, b: a >= b),
           ('<',  lambda a, b: a < b),
           ('>',  lambda a, b: a > b),
           ('=',  lambda a, b: a == b)]

    for op_str, op_fn in ops:
        if condition.startswith(op_str):
            ver = condition[len(op_str):].strip()
            if ver:
                return op_fn(current, parse_version(ver))
    return False


def version_matches_range(current_ver: str, affected_str: str) -> bool:
    """Check if current_ver falls within the affected version range expression.

    Supports: <= X, < X, >= X, > X, = X, ranges (>= X, < Y), OR (||).
    """
    affected_str = affected_str.strip().strip('"').strip("'")
    if not affected_str:
        return False

    current = parse_version(current_ver)

    or_groups = [g.strip() for g in affected_str.split('||')]
    for group in or_groups:
        group = group.strip()
        conditions = re.split(r',\s*', group)

        expanded = []
        for cond in conditions:
            cond = cond.strip()
            tokens = re.findall(r'([<>=]+)\s*([^\s<>=,]+)', cond)
            for op, ver in tokens:
                expanded.append(f"{op} {ver}")

        if not expanded:
            continue

        if all(check_version_condition(current, c) for c in expanded):
            return True

    return False


def load_vulnerabilities(csv_path: Path) -> List[Dict]:
    """Load vulnerabilities from the CSV file."""
    vulns = []
    if not csv_path.exists():
        return vulns
    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            vulns.append({
                'no': row.get('No.', ''),
                'title': row.get('Vulnerability Title', ''),
                'id': row.get('Vulnerability ID', ''),
                'severity': row.get('Severity', ''),
                'affected': row.get('Affected Versions', ''),
                'link': row.get('Vulnerability Link', ''),
            })
    return vulns


SEVERITY_ORDER = {'Critical': 0, 'High': 1, 'Moderate': 2, 'Low': 3}


VULN_CSV_REMOTE_URL = (
    "https://raw.githubusercontent.com/knownsec/openclaw-security/main/docs/openclaw_vulnerabilities.csv"
)


def fetch_vulnerability_csv(target_path: Path) -> bool:
    """Download the latest vulnerability CSV from remote repository."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request(VULN_CSV_REMOTE_URL, headers={
            'User-Agent': 'OpenClaw-Security-Audit/1.0'
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
        with open(target_path, 'wb') as f:
            f.write(data)
        return True
    except Exception:
        return False


def audit_vulnerability_check(result: AuditResult, current_ver: Optional[str]) -> None:
    """Check current OpenClaw version against known vulnerabilities."""
    append_report(f"\n{t('vuln_check_header')}")

    csv_candidates = [
        OC_STATE_DIR / 'workspace' / 'security' / 'ioc-blocklist' / 'openclaw_vulnerabilities.csv',
        Path(__file__).parent.parent / 'docs' / 'openclaw_vulnerabilities.csv',
        Path(__file__).parent / 'openclaw_vulnerabilities.csv',
    ]

    csv_path = None
    for candidate in csv_candidates:
        if candidate.exists():
            csv_path = candidate
            break

    if csv_path is None:
        target = csv_candidates[0]
        if fetch_vulnerability_csv(target):
            csv_path = target
            append_report(f"Local not found, remote fetch: OK ({VULN_CSV_REMOTE_URL})")
        else:
            append_report(t('vuln_csv_not_found', ', '.join(str(p) for p in csv_candidates)))
            result.add_warning(t('vuln_version_unknown'))
            return
    else:
        append_report(f"Loaded: {csv_path}")

    if not current_ver:
        result.add_warning(t('vuln_version_unknown'))
        return

    ver_clean = current_ver.strip().lower()
    for prefix in ['openclaw gateway ', 'openclaw ', 'v']:
        if ver_clean.startswith(prefix):
            ver_clean = ver_clean[len(prefix):]
    # Remove git commit hash in parentheses, e.g. "2026.3.8 (3caab92)" -> "2026.3.8"
    ver_clean = re.sub(r'\s*\([^)]*\)\s*$', '', ver_clean).strip()

    vulns = load_vulnerabilities(csv_path)
    matched = []

    for vuln in vulns:
        affected = vuln.get('affected', '')
        if affected and version_matches_range(ver_clean, affected):
            matched.append(vuln)

    matched.sort(key=lambda v: SEVERITY_ORDER.get(v.get('severity', ''), 99))

    total = len(vulns)
    if not matched:
        append_report(f"\nVersion: {ver_clean}, Checked: {total} vulnerabilities, Matched: 0\n")
        result.add_success(t('vuln_none_matched', ver_clean, total))
    else:
        counts = {}
        for v in matched:
            s = v.get('severity', 'Unknown')
            counts[s] = counts.get(s, 0) + 1

        crit = counts.get('Critical', 0)
        high = counts.get('High', 0)
        mod = counts.get('Moderate', 0)
        low = counts.get('Low', 0)

        append_report(f"\nVersion: {ver_clean}, Checked: {total}, Matched: {len(matched)}\n")
        for v in matched[:30]:
            append_report(t('vuln_detail', severity=v['severity'], id=v['id'], title=v['title']) + '\n')
            append_report(t('vuln_affected', affected=v['affected']) + '\n')
            append_report(t('vuln_link', link=v['link']) + '\n')
            append_report('\n')

        if len(matched) > 30:
            append_report(f"  ... and {len(matched) - 30} more\n")

        summary = t('vuln_matched', ver_clean, len(matched), crit, high, mod, low)
        if crit > 0:
            result.add_warning(f"[CRITICAL] {summary}")
        elif high > 0:
            result.add_warning(summary)
        else:
            result.add_warning(summary)


def check_openclaw_version() -> Tuple[Optional[str], Optional[str]]:
    current_ver = None
    latest_ver = None

    code, output, _ = run_command(['openclaw', '--version'], check=False)
    if output:
        for line in output.split('\n'):
            if line.strip():
                current_ver = line.strip()
                break

    code, output, _ = run_command([
        'openclaw', 'update', '--check'
    ], check=False)

    if output:
        for line in output.split('\n'):
            if 'latest' in line.lower() or 'version' in line.lower():
                latest_ver = line.strip()
                break

    return current_ver, latest_ver


def audit_process_network(result: AuditResult) -> None:
    append_report(f"\n{t('process_network_header')}")

    if IS_WINDOWS:
        # Use netstat on Windows
        _, netstat_output, _ = run_command([
            'netstat', '-ano'
        ], check=False)
        append_report(netstat_output or "netstat command failed")

        # Get top processes by CPU
        _, ps_output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 | Format-Table -AutoSize'
        ], check=False)
        if ps_output:
            append_report("\n" + ps_output)
    elif IS_MACOS:
        # macOS: use netstat and top
        _, netstat_output, _ = run_command([
            'netstat', '-an'
        ], check=False)
        append_report(netstat_output or "netstat command failed")

        # Get top processes (macOS uses -l 1 instead of -b -n 1)
        _, top_output, _ = run_command([
            'top', '-l', '1', '-o', 'cpu', '-n', '15'
        ], check=False)
        if top_output:
            append_report("\n" + top_output)
    else:
        # Linux commands
        _, ss_output, _ = run_command(['ss', '-tunlp'], check=False)
        append_report(ss_output or t('ss_failed'))

        _, top_output, _ = run_command([
            'top', '-b', '-n', '1'
        ], check=False)
        if top_output:
            append_report("\n".join(top_output.split('\n')[:15]))

    result.add_success(t('process_network_ok'))


def audit_sensitive_dirs(result: AuditResult) -> None:
    append_report(f"\n{t('sensitive_dirs_header')}")

    mod_count = 0

    if IS_WINDOWS:
        # Windows: Check user directories
        dirs_to_check = [
            OC_STATE_DIR,
            Path.home() / '.ssh',
        ]

        for dir_path in dirs_to_check:
            if dir_path.exists():
                code, output, _ = run_command([
                    'powershell.exe', '-Command',
                    f'Get-ChildItem -Path "{dir_path}" -Recurse -File -ErrorAction SilentlyContinue | ' +
                    'Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | ' +
                    'Select-Object -ExpandProperty FullName'
                ], check=False)
                if output and output.strip():
                    mod_count += len(output.strip().split('\n'))
    else:
        # Linux: Check all directories including system paths
        dirs_to_check = [
            OC_STATE_DIR,
            Path('/etc'),
            Path.home() / '.ssh',
            Path.home() / '.gnupg',
            Path('/usr/local/bin')
        ]

        for dir_path in dirs_to_check:
            if dir_path.exists():
                _, output, _ = run_command([
                    'find', str(dir_path),
                    '-type', 'f',
                    '-mtime', '-1'
                ], check=False)
                if output:
                    mod_count += len(output.strip().split('\n'))

    append_report(t('total_modified_files', mod_count))
    result.add_success(t('dir_changes', mod_count))


def audit_system_cron(result: AuditResult) -> None:
    append_report(f"\n{t('system_cron_header')}")

    if IS_WINDOWS:
        # Windows Task Scheduler
        code, output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | ' +
            'Select-Object TaskName,Trigger | Format-Table -AutoSize'
        ], check=False)
        append_report(output or "No scheduled tasks found or access denied")
        result.add_success("Windows Task Scheduler: Collected scheduled task info")
        return

    if IS_MACOS:
        # macOS: use launchctl list
        code, output, _ = run_command([
            'launchctl', 'list'
        ], check=False)
        append_report(output or "launchctl command failed")

        # Check user launch agents
        user_agents = Path.home() / 'Library' / 'LaunchAgents'
        if user_agents.exists():
            _, output, _ = run_command(['ls', '-la', str(user_agents)], check=False)
            append_report("\nUser LaunchAgents:\n" + (output or ""))

        result.add_success("macOS launchd: Collected scheduled task info")
        return

    # Linux cron and systemd timers
    cron_dirs = ['/etc/cron.*', '/var/spool/cron/crontabs/']
    for cron_dir in cron_dirs:
        _, output, _ = run_command(['ls', '-la', cron_dir], check=False)
        append_report(output or "")

    _, timers_output, _ = run_command([
        'systemctl', 'list-timers', '--all'
    ], check=False)
    append_report(timers_output or t('systemctl_failed'))

    user_systemd = Path.home() / '.config/systemd/user'
    if user_systemd.exists():
        _, output, _ = run_command(['ls', '-la', str(user_systemd)], check=False)
        append_report(output or "")

    result.add_success(t('system_cron_ok'))


def audit_openclaw_cron(result: AuditResult) -> None:
    append_report(f"\n{t('openclaw_cron_header')}")

    code, stdout, stderr = run_command([
        'openclaw', 'cron', 'list'
    ], check=False)

    append_report(stdout or stderr or t('no_openclaw_cron'))

    if code == 0:
        result.add_success(t('local_cron_ok'))
    else:
        result.add_warning(t('local_cron_failed'))


def audit_ssh(result: AuditResult) -> None:
    append_report(f"\n{t('ssh_header')}")

    if IS_WINDOWS:
        # Windows: Check Event Log for failed login attempts
        code, output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-WinEvent -LogName Security -MaxEvents 100 -ErrorAction SilentlyContinue | ' +
            'Where-Object {$_.Id -eq 4625} | ' +
            'Select-Object TimeCreated,Message | Format-Table -AutoSize'
        ], check=False)

        failed_ssh = 0
        if output:
            failed_ssh = output.strip().count('\n') if output.strip() else 0

        append_report(f"Windows failed login attempts (Event ID 4625): {failed_ssh}")
        result.add_success(t('ssh_security_ok', failed_ssh))
        return

    if IS_MACOS:
        # macOS: Show login records
        _, last_output, _ = run_command(['last', '-n', '5'], check=False)
        append_report(last_output or "last command failed")

        # Check SSH logs using log show
        code, output, _ = run_command([
            'log', 'show', '--predicate', 'process == "sshd"',
            '--last', '24h'
        ], check=False)

        failed_ssh = 0
        if output:
            failed_count = output.lower().count('failed')
            failed_count += output.lower().count('invalid')
            failed_ssh = failed_count

        append_report(f"macOS SSH failed attempts (last 24h): {failed_ssh}")
        result.add_success(t('ssh_security_ok', failed_ssh))
        return

    # Linux SSH audit
    _, last_output, _ = run_command(['last', '-a', '-n', '5'], check=False)
    append_report(last_output or t('last_failed'))

    # SSH failed attempts
    failed_ssh = 0
    _, journal_output, _ = run_command([
        'journalctl', '-u', 'sshd',
        '--since', '24 hours ago'
    ], check=False)

    if journal_output:
        failed_count = journal_output.lower().count('failed')
        failed_count += journal_output.lower().count('invalid')
        failed_ssh = failed_count

    if failed_ssh == 0:
        log_files = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages']
        for log_file in log_files:
            if Path(log_file).exists():
                _, output, _ = run_command([
                    'grep', '-Ei', 'sshd.*(Failed|Invalid)',
                    log_file
                ], check=False)
                if output:
                    failed_ssh = len(output.strip().split('\n'))
                break

    append_report(t('ssh_failed_attempts', failed_ssh))
    result.add_success(t('ssh_security_ok', failed_ssh))


def audit_file_integrity(result: AuditResult) -> None:
    append_report(f"\n{t('file_integrity_header')}")

    baseline_file = OC_STATE_DIR / '.config-baseline.sha256'
    hash_result = t('baseline_not_exist')

    if baseline_file.exists():
        with open(baseline_file, 'r') as f:
            baseline_data = {}
            for line in f:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        baseline_data[parts[1]] = parts[0]

        current_data = {}
        files_to_check = [
            OC_STATE_DIR / 'openclaw.json',
            OC_STATE_DIR / 'devices' / 'paired.json'
        ]

        for file_path in files_to_check:
            if file_path.exists():
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                current_data[str(file_path)] = file_hash

        all_ok = True
        for path, expected_hash in baseline_data.items():
            actual_hash = current_data.get(path)
            if actual_hash is None:
                all_ok = False
                hash_result = t('file_not_exist', path)
                break
            if actual_hash != expected_hash:
                all_ok = False
                hash_result = t('hash_mismatch', path)
                break

        if all_ok and current_data:
            hash_result = t('hash_ok')

    append_report(t('hash_check', hash_result))

    perms = {}
    files_to_check = [
        ('openclaw', OC_STATE_DIR / 'openclaw.json'),
        ('paired', OC_STATE_DIR / 'devices' / 'paired.json'),
    ]

    # Linux-specific files
    if not IS_WINDOWS:
        files_to_check.extend([
            ('sshd_config', Path('/etc/ssh/sshd_config')),
        ])

    # Common files
    files_to_check.append(
        ('authorized_keys', Path.home() / '.ssh' / 'authorized_keys')
    )

    for name, file_path in files_to_check:
        if file_path.exists():
            stat_info = file_path.stat()
            perm_oct = oct(stat_info.st_mode & 0o777)
            perms[name] = perm_oct
        else:
            perms[name] = "N/A"

    perm_str = ", ".join(f"{k}={v}" for k, v in perms.items())
    append_report(t('permissions', perm_str))

    if hash_result == t('hash_ok') and perms.get('openclaw') == '0o600':
        result.add_success(t('baseline_ok'))
    else:
        result.add_warning(t('baseline_warning'))


def audit_yellow_line(result: AuditResult) -> None:
    append_report(f"\n{t('yellow_line_header')}")

    if IS_WINDOWS:
        # Windows: Yellow line audit not applicable in the same way
        # Check PowerShell history instead
        ps_history = Path.home() / 'AppData' / 'Roaming' / 'Microsoft' / 'Windows' / 'PowerShell' / 'PSReadLine' / 'ConsoleHost_history.txt'
        sudo_count = 0
        if ps_history.exists():
            try:
                with open(ps_history, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Count admin-related commands
                    sudo_count = content.lower().count('admin') + content.lower().count('sudo')
            except Exception:
                pass

        memory_file = OC_STATE_DIR / 'workspace' / 'memory' / f'{DATE_STR}.md'
        mem_count = 0
        if memory_file.exists():
            with open(memory_file, 'r', encoding='utf-8') as f:
                content = f.read()
                mem_count = content.lower().count('sudo') + content.lower().count('admin')

        append_report(f"PowerShell history commands: {sudo_count}, Memory logs: {mem_count}")
        result.add_success(t('yellow_line_ok', sudo_count, mem_count))
        return

    if IS_MACOS:
        # macOS: Use log show to check sudo usage
        code, output, _ = run_command([
            'log', 'show', '--predicate', 'process == "sudo"',
            '--last', '24h'
        ], check=False)

        sudo_count = 0
        if output:
            sudo_count = len([line for line in output.split('\n') if line.strip()])

        memory_file = OC_STATE_DIR / 'workspace' / 'memory' / f'{DATE_STR}.md'
        mem_count = 0
        if memory_file.exists():
            with open(memory_file, 'r', encoding='utf-8') as f:
                content = f.read()
                mem_count = content.lower().count('sudo')

        append_report(f"macOS sudo log entries: {sudo_count}, Memory logs: {mem_count}")
        result.add_success(t('yellow_line_ok', sudo_count, mem_count))
        return

    # Linux yellow line audit
    sudo_count = 0
    log_files = ['/var/log/auth.log', '/var/log/secure', '/var/log/messages']

    for log_file in log_files:
        if Path(log_file).exists():
            _, output, _ = run_command([
                'grep', '-Ei', 'sudo.*COMMAND',
                log_file
            ], check=False)
            if output:
                sudo_count = len(output.strip().split('\n'))
            break

    memory_file = OC_STATE_DIR / 'workspace' / 'memory' / f'{DATE_STR}.md'
    mem_count = 0
    if memory_file.exists():
        with open(memory_file, 'r', encoding='utf-8') as f:
            content = f.read()
            mem_count = content.lower().count('sudo')

    append_report(t('sudo_log', sudo_count, mem_count))
    result.add_success(t('yellow_line_ok', sudo_count, mem_count))


def audit_disk_usage(result: AuditResult) -> None:
    append_report(f"\n{t('disk_usage_header')}")

    if IS_WINDOWS:
        # Windows disk usage
        code, output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-PSDrive -PSProvider FileSystem | ' +
            'Select-Object Name,Used,Free,@{Name="Used%";Expression={[math]::Round($_.Used/($_.Used+$_.Free)*100,2)}} | ' +
            'Format-Table -AutoSize'
        ], check=False)

        disk_usage = t('disk_unknown')
        if output:
            for line in output.split('\n'):
                if 'C:' in line or '%' in line:
                    append_report(line.strip())

        # Find large files on C: drive
        code, find_output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-ChildItem -Path C:\\ -Recurse -File -ErrorAction SilentlyContinue | ' +
            'Where-Object {$_.Length -gt 100MB -and $_.LastWriteTime -gt (Get-Date).AddDays(-1)} | ' +
            'Select-Object -First 20 -ExpandProperty FullName'
        ], check=False)

        large_files = 0
        if find_output and find_output.strip():
            large_files = len(find_output.strip().split('\n'))

        append_report(t('disk_usage', disk_usage, large_files))
        result.add_success(t('disk_capacity', disk_usage, large_files))
        return

    # macOS and Linux use similar commands
    _, df_output, _ = run_command(['df', '-h', '/'], check=False)
    disk_usage = t('disk_unknown')
    if df_output:
        lines = df_output.split('\n')
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 5:
                disk_usage = parts[4]

    _, find_output, _ = run_command([
        'find', '/', '-xdev',
        '-type', 'f',
        '-size', '+100M',
        '-mtime', '-1'
    ], check=False)
    large_files = 0
    if find_output:
        large_files = len(find_output.strip().split('\n'))

    append_report(t('disk_usage', disk_usage, large_files))
    result.add_success(t('disk_capacity', disk_usage, large_files))


def audit_env_variables(result: AuditResult) -> None:
    append_report(f"\n{t('env_variables_header')}")

    if IS_WINDOWS:
        # Windows: Get process ID and check environment
        code, pgrep_output, _ = run_command([
            'powershell.exe', '-Command',
            'Get-Process openclaw-gateway -ErrorAction SilentlyContinue | ' +
            'Select-Object -ExpandProperty Id'
        ], check=False)

        gw_pid = None
        if pgrep_output and pgrep_output.strip().isdigit():
            gw_pid = pgrep_output.strip()

        if gw_pid:
            # Windows doesn't allow direct reading of process environment
            # Use a different approach: check if process has certain environment variables
            code, output, _ = run_command([
                'powershell.exe', '-Command',
                f'(Get-Process -Id {gw_pid} -ErrorAction SilentlyContinue).StartInfo.EnvironmentVariables'
            ], check=False)

            # Since we can't easily read env vars on Windows, just log the attempt
            append_report("Environment variable scan: Cannot directly read process environment on Windows (OS limitation)")
            result.add_success(t('env_scan_ok'))
        else:
            result.add_warning(t('env_no_process'))
        return

    if IS_MACOS:
        # macOS: Use ps to get environment variables
        _, pgrep_output, _ = run_command([
            'pgrep', '-f', 'openclaw-gateway'
        ], check=False)

        gw_pid = None
        if pgrep_output and pgrep_output.strip().isdigit():
            gw_pid = pgrep_output.strip()

        if gw_pid:
            # macOS uses ps -E to show environment
            code, output, _ = run_command([
                'ps', '-E', '-p', gw_pid
            ], check=False)

            if output:
                env_data = output
                sensitive_found = []
                for line in env_data.split('\n'):
                    line = line.strip()
                    if line and '=' in line:
                        for keyword in ['SECRET', 'TOKEN', 'PASSWORD', 'KEY']:
                            if keyword in line.upper():
                                var_name = line.split('=')[0]
                                sensitive_found.append(t('env_var_hidden', var_name))
                                break

                if sensitive_found:
                    append_report(t('sensitive_vars_found') + ", ".join(sensitive_found[:5]))
                else:
                    append_report(t('no_sensitive_vars'))

                result.add_success(t('env_scan_ok'))
            else:
                result.add_warning(t('env_cannot_read'))
        else:
            result.add_warning(t('env_no_process'))
        return

    # Linux environment variable audit
    _, pgrep_output, _ = run_command([
        'pgrep', '-f', 'openclaw-gateway'
    ], check=False)

    gw_pid = None
    if pgrep_output:
        pids = pgrep_output.strip().split('\n')
        if pids and pids[0].isdigit():
            gw_pid = pids[0]

    if gw_pid:
        environ_file = Path(f'/proc/{gw_pid}/environ')
        if environ_file.exists():
            with open(environ_file, 'r', encoding='utf-8', errors='ignore') as f:
                env_data = f.read()

            sensitive_found = []
            for line in env_data.split('\x00'):
                if line:
                    for keyword in ['SECRET', 'TOKEN', 'PASSWORD', 'KEY']:
                        if keyword in line.upper():
                            var_name = line.split('=')[0]
                            sensitive_found.append(t('env_var_hidden', var_name))
                            break

            if sensitive_found:
                append_report(t('sensitive_vars_found') + ", ".join(sensitive_found[:5]))
            else:
                append_report(t('no_sensitive_vars'))

            result.add_success(t('env_scan_ok'))
        else:
            result.add_warning(t('env_cannot_read'))
    else:
        result.add_warning(t('env_no_process'))


def audit_dlp(result: AuditResult) -> None:
    append_report(f"\n{t('dlp_header')}")

    import re

    scan_root = OC_STATE_DIR / 'workspace'
    dlp_hits = 0

    if scan_root.exists():
        # Scan Ethereum private key pattern
        eth_pattern = re.compile(r'\b0x[a-fA-F0-9]{64}\b')

        # Scan mnemonic pattern
        mnemonic_pattern = re.compile(
            r'\b([a-z]{3,12}\s+){11,23}([a-z]{3,12})\b'
        )

        for file_path in scan_root.rglob('*'):
            if file_path.is_file():
                if file_path.suffix in {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.zip'}:
                    continue
                if '.git' in file_path.parts:
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    dlp_hits += len(eth_pattern.findall(content))
                    dlp_hits += len(mnemonic_pattern.findall(content))
                except Exception:
                    pass

    append_report(t('dlp_result', dlp_hits))

    if dlp_hits > 0:
        result.add_warning(t('dlp_found', dlp_hits))
    else:
        result.add_success(t('dlp_ok'))


def audit_skill_integrity(result: AuditResult) -> None:
    append_report(f"\n{t('skill_integrity_header')}")

    skill_dir = OC_STATE_DIR / 'workspace' / 'skills'
    mcp_dir = OC_STATE_DIR / 'workspace' / 'mcp'
    hash_dir = OC_STATE_DIR / 'security-baselines'

    hash_dir.mkdir(parents=True, exist_ok=True)

    cur_hash = hash_dir / 'skill-mcp-current.sha256'
    base_hash = hash_dir / 'skill-mcp-baseline.sha256'

    current_hashes = {}
    for check_dir in [skill_dir, mcp_dir]:
        if check_dir.exists():
            for file_path in check_dir.rglob('*'):
                if file_path.is_file():
                    try:
                        with open(file_path, 'rb') as f:
                            file_hash = hashlib.sha256(f.read()).hexdigest()
                        current_hashes[str(file_path)] = file_hash
                    except Exception:
                        pass

    with open(cur_hash, 'w') as f:
        for path, hash_val in sorted(current_hashes.items()):
            f.write(f"{hash_val}  {path}\n")

    if current_hashes:
        if base_hash.exists():
            # compare differences
            with open(base_hash, 'r') as f:
                baseline_hashes = {}
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        baseline_hashes[parts[1]] = parts[0]

            # check for changes
            changes = []
            for path, cur_hash_val in current_hashes.items():
                base_hash_val = baseline_hashes.get(path)
                if base_hash_val is None:
                    changes.append(t('new_addition', path))
                elif base_hash_val != cur_hash_val:
                    changes.append(t('modified', path))

            if changes:
                append_report(t('changes_detected') + "\n".join(changes[:10]))
                result.add_warning(t('integrity_changed'))
            else:
                result.add_success(t('integrity_ok'))
        else:
            # first time generating baseline
            import shutil
            shutil.copy(cur_hash, base_hash)
            result.add_success(t('integrity_first'))
    else:
        result.add_success(t('integrity_no_files'))


def audit_disaster_recovery(result: AuditResult) -> None:
    append_report(f"\n{t('disaster_recovery_header')}")

    git_dir = OC_STATE_DIR / '.git'

    if not git_dir.exists():
        result.add_warning(t('no_git_repo'))
        return

    backup_status = "unknown"

    try:
        os.chdir(OC_STATE_DIR)

        run_command(['git', 'add', '.'], check=False)

        code, stdout, _ = run_command([
            'git', 'diff', '--cached', '--quiet'
        ], check=False)

        if code == 0:
            backup_status = "skip"
            append_report(t('no_changes'))
        else:
            commit_msg = f"OpenClaw daily backup ({DATE_STR})" if not USE_ZH else f"OpenClaw 每日备份 ({DATE_STR})"
            run_command([
                'git', 'commit', '-m', commit_msg
            ], check=False)

            code, _, stderr = run_command([
                'git', 'push', 'origin', 'main'
            ], check=False)

            if code == 0:
                backup_status = "ok"
            else:
                backup_status = "fail"
                append_report(t('backup_failed', stderr))

    except Exception as e:
        append_report(t('backup_error', str(e)))
        backup_status = "error"

    if backup_status == "ok":
        result.add_success(t('backup_ok'))
    elif backup_status == "skip":
        result.add_success(t('backup_skip'))
    else:
        result.add_warning(t('backup_push_failed'))


def send_telegram_report(summary: str) -> bool:
    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID')

    if not bot_token or not chat_id:
        return False

    try:
        import urllib.request
        import urllib.parse

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = urllib.parse.urlencode({
            'chat_id': chat_id,
            'text': summary,
            'parse_mode': 'HTML'
        }).encode()

        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req) as response:
            return response.getcode() == 200
    except Exception as e:
        append_report(f"\n{t('telegram_send_failed', str(e))}")
        return False


def main():
    print(t('report_title', DATE_STR))

    setup_report_dir()
    result = AuditResult()

    write_report(t('report_title', DATE_STR))

    current_ver, latest_ver = check_openclaw_version()
    append_report(f"\n{t('version_info_header')}")
    append_report(t('current_version', current_ver or t('version_unknown')))
    append_report(t('latest_version', latest_ver or t('version_unknown')))
    if current_ver and latest_ver and current_ver != latest_ver:
        result.add_warning(t('version_not_latest', current_ver))
    else:
        result.add_success(t('version_ok', current_ver or t('version_unknown')))

    audit_platform(result)
    audit_isolation(result)
    audit_root_privilege(result)
    audit_gateway_exposure(result)
    audit_process_network(result)
    audit_sensitive_dirs(result)
    audit_system_cron(result)
    audit_openclaw_cron(result)
    audit_ssh(result)
    audit_file_integrity(result)
    audit_yellow_line(result)
    audit_disk_usage(result)
    audit_env_variables(result)
    audit_dlp(result)
    audit_skill_trust(result)
    audit_skill_integrity(result)
    audit_vulnerability_check(result, current_ver)
    audit_disaster_recovery(result)

    summary = result.get_summary()

    print("\n" + summary)
    print(t('detailed_report_saved', REPORT_FILE))

    send_telegram_report(summary)

    return 0


if __name__ == '__main__':
    sys.exit(main())
