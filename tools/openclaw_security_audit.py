#!/usr/bin/env python3

import os
import sys
import json
import hashlib
import subprocess
import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Optional

OC_STATE_DIR = Path(os.environ.get(
    'OPENCLAW_STATE_DIR',
    Path.home() / '.openclaw'
))
REPORT_DIR = Path('/tmp/openclaw-security-reports')
DATE_STR = datetime.date.today().isoformat()
REPORT_FILE = REPORT_DIR / f'report-{DATE_STR}.txt'


class AuditResult:
    """审计结果类"""
    def __init__(self):
        self.summary_lines = []
        self.warnings = []

    def add_success(self, message: str):
        """添加成功信息"""
        self.summary_lines.append(f"[OK] {message}")

    def add_warning(self, message: str):
        """添加警告信息"""
        self.warnings.append(f"[警告] {message}")
        self.summary_lines.append(f"[警告] {message}")

    def get_summary(self) -> str:
        """获取汇总信息"""
        lines = [f"OpenClaw 每日安全巡检简报 ({DATE_STR})", ""]
        lines.extend(self.summary_lines)
        if self.warnings:
            lines.append("")
            lines.append("警告项目：")
            lines.extend(self.warnings)
        return "\n".join(lines)


def run_command(
    cmd: List[str],
    capture: bool = True,
    check: bool = False
) -> Tuple[int, str, str]:
    """
    执行命令并返回结果

    Args:
        cmd: 命令列表
        capture: 是否捕获输出
        check: 是否检查返回码

    Returns:
        (返回码, 标准输出, 标准错误)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr
    except FileNotFoundError:
        return -1, "", "命令未找到"
    except Exception as e:
        return -1, "", str(e)


def setup_report_dir() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)


def write_report(content: str) -> None:
    """写入报告文件"""
    with open(REPORT_FILE, 'w', encoding='utf-8') as f:
        f.write(content)


def append_report(content: str) -> None:
    """追加内容到报告文件"""
    with open(REPORT_FILE, 'a', encoding='utf-8') as f:
        f.write(content)


def audit_platform(result: AuditResult) -> None:
    append_report("\nOpenClaw 基础审计 (--deep)")
    code, stdout, stderr = run_command([
        'openclaw', 'security', 'audit', '--deep'
    ], check=False)

    append_report(stdout or stderr)

    if code == 0:
        result.add_success("平台审计: 已执行原生扫描")
    else:
        result.add_warning("平台审计: 执行失败（详见详细报告）")


def audit_isolation(result: AuditResult) -> None:
    """检测运行环境隔离性"""
    append_report("\n运行环境隔离性检测")

    isolation_info = []
    is_isolated = False

    # 检测 Docker 容器
    docker_path = Path('/.dockerenv')
    if docker_path.exists():
        isolation_info.append("检测到 Docker 容器环境")
        is_isolated = True

    # 检测 cgroup
    _, cgroup_output, _ = run_command(['cat', '/proc/1/cgroup'], check=False)
    if cgroup_output and ('docker' in cgroup_output.lower() or 'kubepods' in cgroup_output.lower()):
        if 'docker' not in isolation_info:
            isolation_info.append("检测到容器环境 (cgroup)")
            is_isolated = True

    # 检测虚拟机
    _, dmi_output, _ = run_command(['cat', '/sys/class/dmi/id/product_name'], check=False)
    if dmi_output:
        vm_keywords = ['vmware', 'virtualbox', 'kvm', 'qemu', 'xen', 'hyper-v']
        for keyword in vm_keywords:
            if keyword in dmi_output.lower():
                isolation_info.append(f"检测到虚拟机环境 ({dmi_output.strip()})")
                is_isolated = True
                break

    # 检测 systemd-detect-virt
    code, virt_output, _ = run_command(['systemd-detect-virt'], check=False)
    if code == 0 and virt_output.strip() != 'none':
        if virt_output.strip() not in str(isolation_info):
            isolation_info.append(f"虚拟化类型: {virt_output.strip()}")
            is_isolated = True

    if isolation_info:
        append_report(" | ".join(isolation_info))
        result.add_success("环境隔离: 运行在隔离环境中")
    else:
        append_report("未检测到虚拟机/容器环境特征")
        result.add_warning("环境隔离: 建议在隔离环境 (VM/Docker) 中运行 OpenClaw")


def audit_root_privilege(result: AuditResult) -> None:
    """检测 root 权限运行"""
    append_report("\n最小权限原则检测")

    is_root = os.geteuid() == 0

    if is_root:
        append_report("当前以 root 身份运行")
        result.add_warning("权限检查: 不建议以 root 身份运行 OpenClaw")
    else:
        append_report("当前以普通用户运行")
        result.add_success("权限检查: 符合最小权限原则")


def audit_gateway_exposure(result: AuditResult) -> None:
    """检测 18789 端口暴露情况"""
    append_report("\nGateway 端口 (18789) 暴露检测")

    _, ss_output, _ = run_command([
        'ss', '-tunlp'
    ], check=False)

    exposed = False
    binding_info = []

    if ss_output:
        for line in ss_output.split('\n'):
            if '18789' in line:
                append_report(f"监听记录: {line.strip()}")
                if '0.0.0.0:18789' in line or '[::]:18789' in line:
                    exposed = True
                    binding_info.append("监听所有接口 (0.0.0.0/::)")
                elif '127.0.0.1:18789' in line or '[::1]:18789' in line:
                    binding_info.append("仅监听本地 (127.0.0.1/::1)")

    if binding_info:
        append_report(" | ".join(binding_info))

    if exposed:
        result.add_warning("端口暴露: 18789 端口监听所有接口，建议绑定 127.0.0.1")
    elif binding_info:
        result.add_success("端口暴露: 18789 端口仅本地监听")
    else:
        append_report("未检测到 18789 端口监听")
        result.add_success("端口暴露: Gateway 未运行或端口未监听")


def audit_skill_trust(result: AuditResult) -> None:
    """检测已安装 Skill 的可信度"""
    append_report("\nSkill 可信来源检测")

    skill_dir = OC_STATE_DIR / 'workspace' / 'skills'

    if not skill_dir.exists():
        append_report("未找到 skills 目录")
        result.add_success("Skill 信任: 无已安装技能")
        return

    # 统计技能数量和来源
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
                # 获取 git remote
                code, remote_output, _ = run_command([
                    'git', '-C', str(skill_path),
                    'remote', '-v'
                ], check=False)
                if remote_output:
                    append_report(f"  [{skill_path.name}] {remote_output.split()[0] if remote_output.split() else 'unknown'}")
            else:
                from_local += 1

    append_report(f"总计: {skill_count} 个技能 (Git来源: {from_git}, 本地: {from_local})")

    if skill_count > 10:
        result.add_warning(f"Skill 信任: 已安装 {skill_count} 个技能，建议定期审查")
    else:
        result.add_success(f"Skill 信任: 已安装 {skill_count} 个技能")


def check_openclaw_version() -> Tuple[Optional[str], Optional[str]]:
    """检查 OpenClaw 当前版本和最新版本"""
    current_ver = None
    latest_ver = None

    # 获取当前版本
    code, output, _ = run_command(['openclaw', '--version'], check=False)
    if output:
        # 尝试解析版本号
        for line in output.split('\n'):
            if line.strip():
                current_ver = line.strip()
                break

    # 获取最新版本 (通过 openclow update --check 或 API)
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
    append_report("\n监听端口与高资源进程")

    # 获取监听端口
    _, ss_output, _ = run_command(['ss', '-tunlp'], check=False)
    append_report(ss_output or "ss 命令执行失败")

    # 获取进程信息
    _, top_output, _ = run_command([
        'top', '-b', '-n', '1'
    ], check=False)
    if top_output:
        append_report("\n".join(top_output.split('\n')[:15]))

    result.add_success("进程网络: 已采集监听端口与进程快照")


def audit_sensitive_dirs(result: AuditResult) -> None:
    append_report("\n敏感目录近 24h 变更文件数")

    dirs_to_check = [
        OC_STATE_DIR,
        Path('/etc'),
        Path.home() / '.ssh',
        Path.home() / '.gnupg',
        Path('/usr/local/bin')
    ]

    mod_count = 0
    for dir_path in dirs_to_check:
        if dir_path.exists():
            _, output, _ = run_command([
                'find', str(dir_path),
                '-type', 'f',
                '-mtime', '-1'
            ], check=False)
            if output:
                mod_count += len(output.strip().split('\n'))

    append_report(f"总计变更文件数: {mod_count}")
    result.add_success(f"目录变更: {mod_count} 个文件 (位于 /etc/ 或 ~/.ssh 等)")


def audit_system_cron(result: AuditResult) -> None:
    append_report("\n系统级定时任务与 Systemd Timers")

    # 检查 cron 目录
    cron_dirs = ['/etc/cron.*', '/var/spool/cron/crontabs/']
    for cron_dir in cron_dirs:
        _, output, _ = run_command(['ls', '-la', cron_dir], check=False)
        append_report(output or "")

    # 检查 systemd timers
    _, timers_output, _ = run_command([
        'systemctl', 'list-timers', '--all'
    ], check=False)
    append_report(timers_output or "systemctl 命令执行失败")

    # 检查用户 systemd
    user_systemd = Path.home() / '.config/systemd/user'
    if user_systemd.exists():
        _, output, _ = run_command(['ls', '-la', str(user_systemd)], check=False)
        append_report(output or "")

    result.add_success("系统 Cron: 已采集系统级定时任务信息")


def audit_openclaw_cron(result: AuditResult) -> None:
    append_report("\nOpenClaw Cron Jobs")

    code, stdout, stderr = run_command([
        'openclaw', 'cron', 'list'
    ], check=False)

    append_report(stdout or stderr or "未找到 openclaw cron 命令")

    if code == 0:
        result.add_success("本地 Cron: 已拉取内部任务列表")
    else:
        result.add_warning("本地 Cron: 拉取失败（可能是 token/权限问题）")


def audit_ssh(result: AuditResult) -> None:
    append_report("\n最近登录记录与 SSH 失败尝试")

    _, last_output, _ = run_command(['last', '-a', '-n', '5'], check=False)
    append_report(last_output or "last 命令执行失败")

    # SSH 失败尝试
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

    append_report(f"SSH 失败尝试 (近24h): {failed_ssh}")
    result.add_success(f"SSH 安全: 近24h 失败尝试 {failed_ssh} 次")


def audit_file_integrity(result: AuditResult) -> None:
    """关键文件完整性与权限"""
    append_report("\n关键配置文件权限与哈希基线")

    baseline_file = OC_STATE_DIR / '.config-baseline.sha256'
    hash_result = "基线文件不存在"

    if baseline_file.exists():
        with open(baseline_file, 'r') as f:
            baseline_data = {}
            for line in f:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        baseline_data[parts[1]] = parts[0]

        # 计算当前文件哈希
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
                hash_result = f"文件不存在: {path}"
                break
            if actual_hash != expected_hash:
                all_ok = False
                hash_result = f"哈希不匹配: {path}"
                break

        if all_ok and current_data:
            hash_result = "OK"

    append_report(f"哈希校验: {hash_result}")

    # 检查权限
    perms = {}
    files_to_check = [
        ('openclaw', OC_STATE_DIR / 'openclaw.json'),
        ('paired', OC_STATE_DIR / 'devices' / 'paired.json'),
        ('sshd_config', Path('/etc/ssh/sshd_config')),
        ('authorized_keys', Path.home() / '.ssh' / 'authorized_keys')
    ]

    for name, file_path in files_to_check:
        if file_path.exists():
            stat_info = file_path.stat()
            perm_oct = oct(stat_info.st_mode & 0o777)
            perms[name] = perm_oct
        else:
            perms[name] = "N/A"

    perm_str = ", ".join(f"{k}={v}" for k, v in perms.items())
    append_report(f"权限: {perm_str}")

    if hash_result == "OK" and perms.get('openclaw') == '0o600':
        result.add_success("配置基线: 哈希校验通过且权限合规")
    else:
        result.add_warning("配置基线: 基线缺失/校验异常或权限不合规")


def audit_yellow_line(result: AuditResult) -> None:
    append_report("\n黄线操作对比 (sudo logs vs memory)")

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

    append_report(f"Sudo 日志: {sudo_count}, Memory 日志: {mem_count}")
    result.add_success(f"黄线审计: sudo记录={sudo_count}, memory记录={mem_count}")


def audit_disk_usage(result: AuditResult) -> None:
    append_report("\n磁盘使用率与最近大文件")

    _, df_output, _ = run_command(['df', '-h', '/'], check=False)
    disk_usage = "未知"
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

    append_report(f"磁盘使用: {disk_usage}, 大文件 (>100M): {large_files}")
    result.add_success(f"磁盘容量: 根分区占用 {disk_usage}, 新增 {large_files} 个大文件")


def audit_env_variables(result: AuditResult) -> None:
    append_report("\nGateway 环境变量泄露扫描")

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
                            sensitive_found.append(f"{var_name}=(已隐藏)")
                            break

            if sensitive_found:
                append_report("发现敏感环境变量: " + ", ".join(sensitive_found[:5]))
            else:
                append_report("未发现明显的敏感变量名")

            result.add_success("环境变量: 已执行网关进程敏感变量名扫描")
        else:
            result.add_warning("环境变量: 无法读取进程环境文件")
    else:
        result.add_warning("环境变量: 未定位到 openclaw-gateway 进程")


def audit_dlp(result: AuditResult) -> None:
    append_report("\n明文私钥/助记词泄露扫描 (DLP)")

    import re

    scan_root = OC_STATE_DIR / 'workspace'
    dlp_hits = 0

    if scan_root.exists():
        # 扫描以太坊私钥模式 (0x + 64 hex)
        eth_pattern = re.compile(r'\b0x[a-fA-F0-9]{64}\b')

        # 扫描助记词模式 (12/24 个小写单词)
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

    append_report(f"DLP 扫描结果: {dlp_hits}")

    if dlp_hits > 0:
        result.add_warning(f"敏感凭证扫描: 检测到疑似明文敏感信息({dlp_hits})，请人工复核")
    else:
        result.add_success("敏感凭证扫描: 未发现明显私钥/助记词模式")


def audit_skill_integrity(result: AuditResult) -> None:
    append_report("\nSkill/MCP 完整性基线对比")

    skill_dir = OC_STATE_DIR / 'workspace' / 'skills'
    mcp_dir = OC_STATE_DIR / 'workspace' / 'mcp'
    hash_dir = OC_STATE_DIR / 'security-baselines'

    hash_dir.mkdir(parents=True, exist_ok=True)

    cur_hash = hash_dir / 'skill-mcp-current.sha256'
    base_hash = hash_dir / 'skill-mcp-baseline.sha256'

    # 计算当前哈希
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

    # 写入当前哈希文件
    with open(cur_hash, 'w') as f:
        for path, hash_val in sorted(current_hashes.items()):
            f.write(f"{hash_val}  {path}\n")

    if current_hashes:
        if base_hash.exists():
            # 比较差异
            with open(base_hash, 'r') as f:
                baseline_hashes = {}
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        baseline_hashes[parts[1]] = parts[0]

            # 检查是否有变化
            changes = []
            for path, cur_hash_val in current_hashes.items():
                base_hash_val = baseline_hashes.get(path)
                if base_hash_val is None:
                    changes.append(f"新增: {path}")
                elif base_hash_val != cur_hash_val:
                    changes.append(f"变更: {path}")

            if changes:
                append_report("检测到变化:\n" + "\n".join(changes[:10]))
                result.add_warning("Skill/MCP基线: 检测到文件哈希变化（详见diff）")
            else:
                result.add_success("Skill/MCP基线: 与上次基线一致")
        else:
            # 首次生成基线
            import shutil
            shutil.copy(cur_hash, base_hash)
            result.add_success("Skill/MCP基线: 首次生成基线完成")
    else:
        result.add_success("Skill/MCP基线: 未发现 skills/mcp 目录文件")


def audit_disaster_recovery(result: AuditResult) -> None:
    append_report("\n大脑灾备 (Git Backup)")

    git_dir = OC_STATE_DIR / '.git'

    if not git_dir.exists():
        result.add_warning("灾备备份: 未初始化 Git 仓库，已跳过")
        return

    backup_status = "unknown"

    try:
        os.chdir(OC_STATE_DIR)

        # git add
        run_command(['git', 'add', '.'], check=False)

        # 检查是否有变更
        code, stdout, _ = run_command([
            'git', 'diff', '--cached', '--quiet'
        ], check=False)

        if code == 0:
            backup_status = "skip"
            append_report("无新变更，跳过提交")
        else:
            # 有变更，提交并推送
            commit_msg = f"OpenClaw 每日备份 ({DATE_STR})"
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
                append_report(f"推送失败: {stderr}")

    except Exception as e:
        append_report(f"备份过程出错: {str(e)}")
        backup_status = "error"

    if backup_status == "ok":
        result.add_success("灾备备份: 已自动推送至远端仓库")
    elif backup_status == "skip":
        result.add_success("灾备备份: 无新变更，跳过推送")
    else:
        result.add_warning("灾备备份: 推送失败（不影响本次巡检）")


def send_telegram_report(summary: str) -> bool:
    """发送 Telegram 报告"""
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
        append_report(f"\nTelegram 发送失败: {str(e)}")
        return False


def main():
    """主函数"""
    print(f"=== OpenClaw 安全审计详细报告 ({DATE_STR}) ===")

    setup_report_dir()
    result = AuditResult()

    write_report(f"=== OpenClaw 安全审计详细报告 ({DATE_STR}) ===")

    current_ver, latest_ver = check_openclaw_version()
    append_report(f"\nOpenClaw 版本信息")
    append_report(f"当前版本: {current_ver or '未知'}")
    append_report(f"最新版本: {latest_ver or '未知'}")
    if current_ver and latest_ver and current_ver != latest_ver:
        result.add_warning(f"版本检查: 当前版本 {current_ver} 非最新版本，建议升级")
    else:
        result.add_success(f"版本检查: 当前版本 {current_ver or '未知'}")

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
    audit_disaster_recovery(result)

    summary = result.get_summary()

    print("\n" + summary)
    print(f"\n详细报告已保存至: {REPORT_FILE}")

    # 尝试发送 Telegram
    send_telegram_report(summary)

    return 0


if __name__ == '__main__':
    sys.exit(main())
