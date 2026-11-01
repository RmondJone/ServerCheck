# -*- coding: utf-8 -*-
"""
暴力破解与登录审计模块
检测项：
1. 最近 SSH 登录失败与暴力破解报告 (统计概览 + 最近失败详细流水)
2. 最近 SSH 登录成功报告 (日志 Accepted 事件与 last pts 远程会话审计 + 公网 IP 预警)
3. 当前在线活跃登录会话审计 (who / w)
4. MySQL / MariaDB 数据库外部暴力破解排查
5. Redis 缓存服务外部认证爆破与未授权探测排查
6. Web 应用后台登录爆破与敏感路径恶意扫描排查 (Nginx / Apache)
7. FTP 服务暴力破解排查 (vsftpd / proftpd / pure-ftpd)
"""

import os
import re
import glob
import gzip
from collections import Counter
from typing import List, Tuple, Dict, Any
from core.base import BaseModule
from core.utils import run_cmd, read_file_safe, is_private_ip, is_root, is_darwin, is_linux
from config import Severity, BRUTE_FORCE_CONFIG, SERVICES_BRUTE_FORCE_CONFIG

class BruteForceCheck(BaseModule):
    name = "BruteForceCheck"
    description = "多服务暴力破解与登录历史审计"

    def run(self):
        log_lines, has_perm_denied = self._get_log_lines()
        
        # 1. SSH 失败与成功登录审计 (默认必出)
        self._check_ssh_failed_logins(log_lines, has_perm_denied)
        self._check_ssh_successful_logins(log_lines, has_perm_denied)
        
        # 2. 当前在线用户会话
        self._check_current_users()

        # 3. 常见外部应用服务爆破排查 (MySQL / Redis / Web / FTP)
        checked_services = []
        if self._check_mysql_bruteforce():
            checked_services.append("MySQL")
        if self._check_redis_bruteforce():
            checked_services.append("Redis")
        if self._check_web_bruteforce():
            checked_services.append("Web(Nginx/Apache)")
        if self._check_ftp_bruteforce():
            checked_services.append("FTP")

        # 若未检测到任何上述服务的独立日志，生成汇总审计报告
        if not checked_services:
            self._add_services_summary_finding()

        return self.findings

    def _extract_timestamp(self, line: str) -> str:
        """从日志行中提取时间戳，规范化输出"""
        m_iso = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
        if m_iso:
            return m_iso.group(1).replace("T", " ")
        m_syslog = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
        if m_syslog:
            return m_syslog.group(1)
        return "未知时间"

    def _get_ssh_log_lines(self) -> Tuple[List[str], bool]:
        """尝试读取 SSH 认证日志，返回 (有效日志行列表, 是否权限受限)"""
        lines: List[str] = []
        has_perm_denied = False

        if is_darwin():
            if os.path.exists("/var/log/system.log"):
                sys_lines = read_file_safe("/var/log/system.log", max_lines=3000)
                sshd_lines = [l for l in sys_lines if "sshd" in l and not l.startswith("[Permission Denied]")]
                if sshd_lines:
                    lines.extend(sshd_lines)
            if not lines:
                code, out, _ = run_cmd("/usr/bin/log show --predicate 'process == \"sshd\"' --style syslog --last 1d 2>/dev/null", timeout=6)
                if code == 0 and out.strip():
                    lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Filtering the log data") and not l.startswith("Skipping info")]
            return lines, False

        for path_pattern in BRUTE_FORCE_CONFIG.get("auth_log_paths", []):
            for file_path in glob.glob(path_pattern):
                if os.path.exists(file_path):
                    try:
                        if file_path.endswith(".gz"):
                            with gzip.open(file_path, "rt", encoding="utf-8", errors="replace") as f:
                                for line in f:
                                    lines.append(line.rstrip("\r\n"))
                        else:
                            content = read_file_safe(file_path)
                            for c in content:
                                if c.startswith("[Permission Denied]"):
                                    has_perm_denied = True
                                else:
                                    lines.append(c)
                    except Exception:
                        pass

        if not lines:
            code, out, _ = run_cmd("journalctl -u ssh -u sshd --no-pager -n 5000 2>/dev/null", timeout=10)
            if code == 0 and out.strip():
                lines = [l for l in out.splitlines() if l.strip()]
                has_perm_denied = False

        return lines, has_perm_denied

    # 兼容别名
    _get_log_lines = _get_ssh_log_lines

    def _check_ssh_failed_logins(self, log_lines: List[str], has_perm_denied: bool):
        """审计最近 SSH 登录失败与暴力破解记录 (默认必出)"""
        failed_events: List[Dict[str, Any]] = []
        failed_ip_counter = Counter()
        target_user_counter = Counter()

        p_failed = re.compile(
            r"Failed\s+(password|publickey)\s+for\s+(invalid user\s+)?([^\s]+)\s+from\s+([0-9a-fA-F\.:]+)(?:\s+port\s+(\d+))?"
        )
        p_invalid = re.compile(
            r"Invalid user\s+([^\s]+)\s+from\s+([0-9a-fA-F\.:]+)(?:\s+port\s+(\d+))?"
        )
        p_pam = re.compile(
            r"authentication failure;.*rhost=([0-9a-fA-F\.:]+)(?:.*user=([^\s]+))?"
        )

        seen_keys = set()
        for line in reversed(log_lines):
            t_str = self._extract_timestamp(line)
            m = p_failed.search(line)
            if m:
                method, is_invalid, user, ip, port = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5) or "-"
                reason = f"密码错误 (Failed {method})" if not is_invalid else f"非法账号且密码错误 (Invalid user + Failed {method})"
                user_label = f"{user} (非法用户)" if is_invalid else user
                failed_ip_counter[ip] += 1
                target_user_counter[user] += 1
                key = (user, ip, t_str[:19], "failed")
                if key not in seen_keys:
                    seen_keys.add(key)
                    failed_events.append({
                        "time": t_str, "user": user_label, "ip": ip, "port": port, "reason": reason, "is_external": not is_private_ip(ip)
                    })
                continue

            m = p_invalid.search(line)
            if m:
                user, ip, port = m.group(1), m.group(2), m.group(3) or "-"
                failed_ip_counter[ip] += 1
                target_user_counter[user] += 1
                key = (user, ip, t_str[:19], "invalid")
                if key not in seen_keys:
                    seen_keys.add(key)
                    failed_events.append({
                        "time": t_str, "user": f"{user} (非法用户)", "ip": ip, "port": port, "reason": "探测不存在的账号 (Invalid user)", "is_external": not is_private_ip(ip)
                    })
                continue

            m = p_pam.search(line)
            if m:
                ip = m.group(1)
                user = m.group(2) or "未知"
                failed_ip_counter[ip] += 1
                target_user_counter[user] += 1
                key = (user, ip, t_str[:19], "pam")
                if key not in seen_keys:
                    seen_keys.add(key)
                    failed_events.append({
                        "time": t_str, "user": user, "ip": ip, "port": "-", "reason": "PAM底层认证失败 (PAM failure)", "is_external": not is_private_ip(ip)
                    })
                continue

        code, out, _ = run_cmd("lastb -n 30 2>/dev/null", timeout=5)
        if code == 0 and out.strip():
            for line in out.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("btmp begins"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    u, tty, host_or_ip = parts[0], parts[1], parts[2]
                    time_info = " ".join(parts[3:])
                    if re.match(r"^[0-9a-fA-F\.:]+$", host_or_ip):
                        key = (u, host_or_ip, time_info[:12], "lastb")
                        if key not in seen_keys:
                            seen_keys.add(key)
                            failed_ip_counter[host_or_ip] += 1
                            target_user_counter[u] += 1
                            failed_events.append({
                                "time": time_info, "user": u, "ip": host_or_ip, "port": "-", "reason": f"登录认证失败 (lastb {tty})", "is_external": not is_private_ip(host_or_ip)
                            })

        total_failed_attempts = sum(failed_ip_counter.values())
        top_ips = failed_ip_counter.most_common(10)
        top_users = target_user_counter.most_common(10)
        max_single_ip_attempts = top_ips[0][1] if top_ips else 0

        high_threshold = BRUTE_FORCE_CONFIG.get("high_risk_threshold", 50)
        threshold = BRUTE_FORCE_CONFIG.get("failure_threshold", 10)
        limit_display = BRUTE_FORCE_CONFIG.get("recent_display_limit", 15)
        display_events = failed_events[:limit_display]

        if total_failed_attempts > 0:
            if total_failed_attempts >= 100 or max_single_ip_attempts >= high_threshold:
                severity = Severity.HIGH
                title = f"最近 SSH 登录失败与爆破报告 (高危！检测到 {total_failed_attempts} 次失败尝试)"
                desc = f"检测到服务器历史上遭受持续剧烈的 SSH 暴力破解攻击！累计检测到 {total_failed_attempts} 次失败尝试，涉及 {len(failed_ip_counter)} 个攻击源 IP。"
            elif total_failed_attempts >= threshold:
                severity = Severity.MEDIUM
                title = f"最近 SSH 登录失败报告 (中危: 存在多次失败探测，共 {total_failed_attempts} 次)"
                desc = f"检测到服务器存在 SSH 认证失败记录（共 {total_failed_attempts} 次，涉及 {len(failed_ip_counter)} 个来源 IP），可能存在持续扫描或口令探测。"
            else:
                severity = Severity.LOW
                title = f"最近 SSH 登录失败报告 (低危: 少量偶发失败，共 {total_failed_attempts} 次)"
                desc = f"检测到少量 SSH 认证失败记录（共 {total_failed_attempts} 次），通常属于正常偶发输错密码或外部轻微探测。"

            sugg = (
                "1. 修改默认 SSH 端口（将默认 22 改为高位非常规端口，可抵御 95% 以上全网无脑爆破）\n"
                "2. 禁用 root 远程密码登录（配置 /etc/ssh/sshd_config 中的 PermitRootLogin prohibit-password 或 no）\n"
                "3. 全面使用 SSH 密钥认证并关闭密码认证（PasswordAuthentication no）\n"
                "4. 安装并启用 Fail2ban / denyhosts，或在防火墙/安全组配置白名单限制访问源"
            )

            evidence_parts = [
                f"=== SSH 失败与爆破统计概览 ===",
                f"累计失败次数: {total_failed_attempts} 次 | 涉及独立攻击 IP: {len(failed_ip_counter)} 个"
            ]
            if top_ips:
                evidence_parts.append("Top 攻击源 IP:")
                for ip, cnt in top_ips[:5]:
                    ext_tag = "外部公网⚠️" if not is_private_ip(ip) else "内网"
                    evidence_parts.append(f"  - {ip}: {cnt} 次 ({ext_tag})")
            if top_users:
                evidence_parts.append("Top 受针对探测账号:")
                for u, cnt in top_users[:5]:
                    evidence_parts.append(f"  - {u}: {cnt} 次")

            evidence_parts.append(f"\n=== 最近 SSH 登录失败流水 (按时间倒序，显示前 {len(display_events)}/{len(failed_events)} 条) ===")
            for idx, ev in enumerate(display_events, start=1):
                ip_tag = "外部公网⚠️" if ev["is_external"] else "局域网/内网"
                port_str = f":{ev['port']}" if ev['port'] != "-" else ""
                evidence_parts.append(
                    f"[{idx:02d}] 时间: {ev['time']} | 账号: {ev['user']} | 来源: {ev['ip']}{port_str} ({ip_tag}) | 原因: {ev['reason']}"
                )

            self.add_finding(
                title=title,
                severity=severity,
                description=desc,
                detail={
                    "total_failed_attempts": total_failed_attempts,
                    "unique_attacker_ips": len(failed_ip_counter),
                    "top_attacker_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
                    "top_targeted_users": [{"user": user, "count": count} for user, count in top_users],
                    "recent_failures": display_events
                },
                suggestion=sugg,
                raw_evidence="\n".join(evidence_parts)
            )
        else:
            if has_perm_denied and not is_root():
                self.add_finding(
                    title="最近 SSH 登录失败报告 (权限受限)",
                    severity=Severity.INFO,
                    description="未以 root / sudo 权限运行，无权读取系统安全认证日志 (/var/log/auth.log, /var/log/secure 等)，无法审计 SSH 失败与爆破行为。",
                    suggestion="请使用 sudo python3 main.py 重新运行以获取系统安全日志读取权限。"
                )
            else:
                self.add_finding(
                    title="最近 SSH 登录失败报告 (近期无登录失败记录)",
                    severity=Severity.INFO,
                    description="在当前审计的系统认证日志与 btmp 历史中未发现明显的 SSH 密码尝试失败、非法用户探测或暴力破解记录，系统认证防护状态良好。",
                    suggestion="继续保持良好安全习惯，如禁用密码登录、改用 SSH 密钥认证并定期巡检。",
                    raw_evidence="系统认证日志中未检测到近期 SSH 认证失败或暴力破解尝试。"
                )

    def _check_ssh_successful_logins(self, log_lines: List[str], has_perm_denied: bool):
        """审计最近 SSH 登录成功记录 (默认必出)"""
        successful_records: List[Dict[str, Any]] = []
        seen_keys = set()

        p_accepted = re.compile(
            r"Accepted\s+([^\s]+)\s+for\s+(?:invalid user\s+)?([^\s]+)\s+from\s+([0-9a-fA-F\.:]+)(?:\s+port\s+(\d+))?"
        )

        for line in reversed(log_lines):
            m = p_accepted.search(line)
            if m:
                method, user, ip, port = m.group(1), m.group(2), m.group(3), m.group(4) or "-"
                t_str = self._extract_timestamp(line)
                key = (user, ip, t_str[:16])
                if key not in seen_keys:
                    seen_keys.add(key)
                    successful_records.append({
                        "time": t_str,
                        "user": user,
                        "ip": ip,
                        "port": port,
                        "method": f"{method} 认证",
                        "source": "auth_log",
                        "is_external": not is_private_ip(ip)
                    })

        last_limit = BRUTE_FORCE_CONFIG.get("last_login_limit", 50)
        code, out, _ = run_cmd(f"last -n {last_limit} -F 2>/dev/null || last -n {last_limit} 2>/dev/null", timeout=5)
        if code == 0 and out.strip():
            for line in out.strip().splitlines():
                line = line.strip()
                if not line or line.startswith("reboot") or line.startswith("shutdown") or line.startswith("wtmp begins") or line.startswith("btmp begins"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    user = parts[0]
                    tty = parts[1]
                    host_or_ip = parts[2]

                    is_ssh_session = False
                    if tty.startswith("pts/"):
                        is_ssh_session = True
                    elif tty.startswith("ttys") and (re.match(r"^[0-9a-fA-F\.:]+$", host_or_ip) or "." in host_or_ip):
                        if not host_or_ip.startswith("127.") and host_or_ip not in (":0", "console"):
                            is_ssh_session = True
                    elif re.match(r"^[0-9a-fA-F\.:]+$", host_or_ip) and not host_or_ip.startswith("127."):
                        is_ssh_session = True

                    if is_ssh_session:
                        time_and_status = " ".join(parts[3:])
                        key = (user, host_or_ip, time_and_status[:12])
                        if key not in seen_keys:
                            seen_keys.add(key)
                            successful_records.append({
                                "time": time_and_status,
                                "user": user,
                                "ip": host_or_ip,
                                "port": "-",
                                "method": f"SSH终端会话 ({tty})",
                                "source": "last_wtmp",
                                "is_external": not is_private_ip(host_or_ip)
                            })

        limit_display = BRUTE_FORCE_CONFIG.get("recent_display_limit", 15)
        display_records = successful_records[:limit_display]
        external_logins = [r for r in successful_records if r["is_external"]]

        if successful_records:
            if external_logins:
                severity = Severity.MEDIUM
                title = f"最近 SSH 登录成功报告 (共 {len(successful_records)} 条，包含公网 IP 登录)"
                desc = f"审计发现近期有 {len(successful_records)} 次 SSH 成功登录，其中包含 {len(external_logins)} 条来自外部公网 IP 的登录记录！"
                sugg = (
                    "1. 请立即核对公网 IP 是否为管理员日常办公网络出口 IP；\n"
                    "2. 若存在未知外部公网 IP，说明账号密码或私钥已泄露，服务器可能已被控制！请立刻阻断并排查命令历史；\n"
                    "3. 建议配置安全组或防火墙 IP 白名单，仅允许受信网络访问 SSH 端口。"
                )
            else:
                severity = Severity.INFO
                title = f"最近 SSH 登录成功报告 (共 {len(successful_records)} 条)"
                desc = f"审计发现近期有 {len(successful_records)} 次 SSH 成功登录，所有登录来源均来自内网或本地安全私网段，未发现可疑公网登录。"
                sugg = "建议继续保持良好运维规范，优先使用 SSH 密钥认证并定期轮换密钥。"

            evidence_lines = [
                f"=== 最近 SSH 成功登录流水 (按时间倒序，显示前 {len(display_records)}/{len(successful_records)} 条) ==="
            ]
            for idx, r in enumerate(display_records, start=1):
                ip_tag = "外部公网⚠️" if r["is_external"] else "局域网/内网"
                port_str = f" | 端口: {r['port']}" if r["port"] != "-" else ""
                evidence_lines.append(
                    f"[{idx:02d}] 时间: {r['time']} | 用户: {r['user']} | 来源: {r['ip']} ({ip_tag}) | 认证: {r['method']}{port_str}"
                )

            self.add_finding(
                title=title,
                severity=severity,
                description=desc,
                detail={
                    "total_success_count": len(successful_records),
                    "external_count": len(external_logins),
                    "records": display_records
                },
                suggestion=sugg,
                raw_evidence="\n".join(evidence_lines)
            )
        else:
            if has_perm_denied and not is_root():
                self.add_finding(
                    title="最近 SSH 登录成功报告 (权限受限)",
                    severity=Severity.INFO,
                    description="未以 root / sudo 权限运行，无权读取系统认证日志 (/var/log/auth.log 或 /var/log/secure)，且未能从会话审计中获取到 SSH 成功登录记录。",
                    suggestion="建议使用 sudo python3 main.py 重新运行以获取完整日志读取权限。"
                )
            else:
                self.add_finding(
                    title="最近 SSH 登录成功报告 (近期无成功登录记录)",
                    severity=Severity.INFO,
                    description="在当前审计的系统认证日志与终端会话历史中，未发现 SSH 远程登录成功记录（可能近期未发生远程连接、未开启 SSH 服务，或历史日志已归档）。",
                    suggestion="如服务器确有日常 SSH 远程管理，建议确认 sshd 服务运行状态及系统日志服务 (rsyslog/systemd-journald) 配置。",
                    raw_evidence="系统日志及终端会话历史中未检测到近期 SSH 成功登录记录。"
                )

    def _check_current_users(self):
        """检查当前在线活跃登录会话 (who / w)"""
        code, out, _ = run_cmd("who -u || w -h", timeout=5)
        if code == 0 and out.strip():
            lines = [l for l in out.strip().splitlines() if l.strip()]
            self.add_finding(
                title=f"当前在线活跃登录会话 (共 {len(lines)} 个终端)",
                severity=Severity.INFO,
                description=f"当前系统有 {len(lines)} 个活跃登录终端，请核对是否皆为授权管理员会话。",
                detail={"active_sessions": lines},
                raw_evidence=out.strip(),
                suggestion="如发现未知登录 IP 或非工作时间的终端会话，可通过 pkill -kill -t <tty> 强制踢出会话并及时修改账号凭证。"
            )
        else:
            self.add_finding(
                title="当前在线活跃登录会话 (无活跃用户)",
                severity=Severity.INFO,
                description="当前系统未检测到正在登录的在线交互式终端会话。",
                raw_evidence="当前无活跃登录终端。"
            )

    # =========================================================================
    # 扩展外部服务爆破排查：MySQL / Redis / Web / FTP
    # =========================================================================

    def _collect_files(self, patterns: List[str], max_files: int = 3) -> List[str]:
        """收集匹配的文件列表，按修改时间降序排列"""
        found = []
        for pat in patterns:
            for p in glob.glob(pat):
                if os.path.exists(p) and os.path.isfile(p):
                    found.append(p)
        # 按修改时间从新到旧
        found.sort(key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0, reverse=True)
        return found[:max_files]

    def _read_recent_lines(self, filepath: str, max_lines: int = 5000) -> List[str]:
        """读取文件最新内容行"""
        if filepath.endswith(".gz"):
            try:
                with gzip.open(filepath, "rt", encoding="utf-8", errors="replace") as f:
                    return [line.rstrip("\r\n") for line in f][-max_lines:]
            except Exception:
                return []
        return read_file_safe(filepath, max_lines=max_lines)

    def _check_mysql_bruteforce(self) -> bool:
        """排查 MySQL / MariaDB 数据库外部认证失败与爆破"""
        files = self._collect_files(SERVICES_BRUTE_FORCE_CONFIG.get("mysql_log_paths", []))
        if not files:
            return False

        all_lines = []
        for f in files:
            all_lines.extend(self._read_recent_lines(f, max_lines=4000))

        # 匹配 MySQL Access denied
        p_mysql = re.compile(r"Access denied for user '([^']+)'@'([0-9a-fA-F\.:]+)'")
        fails = []
        ip_counter = Counter()
        user_counter = Counter()

        for line in reversed(all_lines):
            m = p_mysql.search(line)
            if m:
                u, ip = m.group(1), m.group(2)
                t_str = self._extract_timestamp(line)
                fails.append({"time": t_str, "user": u, "ip": ip, "is_external": not is_private_ip(ip)})
                ip_counter[ip] += 1
                user_counter[u] += 1

        total = len(fails)
        top_ips = ip_counter.most_common(5)
        top_users = user_counter.most_common(5)

        if total > 0:
            if total >= 20 or (top_ips and top_ips[0][1] >= 10):
                severity = Severity.HIGH
                title = f"检测到 MySQL 数据库暴力破解尝试 (高危: 累计 {total} 次失败)"
            else:
                severity = Severity.MEDIUM
                title = f"检测到 MySQL 数据库认证失败记录 (共 {total} 次)"

            evidence_parts = [
                f"=== MySQL 认证失败统计 ===",
                f"累计失败次数: {total} 次 | 涉及攻击源 IP: {len(ip_counter)} 个",
            ]
            if top_ips:
                evidence_parts.append("Top 攻击源 IP:")
                for ip, cnt in top_ips:
                    ext = "外部公网⚠️" if not is_private_ip(ip) else "内网"
                    evidence_parts.append(f"  - {ip}: {cnt} 次 ({ext})")
            if top_users:
                evidence_parts.append("Top 受针对探测账号:")
                for u, cnt in top_users:
                    evidence_parts.append(f"  - {u}: {cnt} 次")

            evidence_parts.append(f"\n=== 最近 MySQL 认证失败流水 (显示最近 10 条) ===")
            for idx, item in enumerate(fails[:10], start=1):
                ext = "外部公网⚠️" if item["is_external"] else "内网"
                evidence_parts.append(f"[{idx:02d}] 时间: {item['time']} | 账号: {item['user']} | 来源: {item['ip']} ({ext})")

            self.add_finding(
                title=title,
                severity=severity,
                description=f"在 MySQL / MariaDB 错误日志中排查到针对数据库账号的认证失败与密码爆破尝试（共 {total} 次）。",
                detail={"total_fails": total, "top_ips": top_ips, "top_users": top_users},
                suggestion=(
                    "1. 严禁 root 用户允许远程公网主机登录 (设置 host='localhost')；\n"
                    "2. 修改 MySQL 默认 3306 端口，或配置安全组禁止 3306 暴露在 0.0.0.0 公网；\n"
                    "3. 限制数据库账号仅允许业务 Web 服务器 IP 白名单连接。"
                ),
                raw_evidence="\n".join(evidence_parts)
            )
        else:
            self.add_finding(
                title="MySQL 数据库认证安全审计 (未检测到爆破尝试)",
                severity=Severity.INFO,
                description="已成功读取 MySQL / MariaDB 错误日志，未发现外部针对数据库账户的高频密码猜测或爆破行为。",
                raw_evidence="MySQL 错误日志中未检测到 Access denied 认证拒绝记录。"
            )
        return True

    def _check_redis_bruteforce(self) -> bool:
        """排查 Redis 缓存服务外部认证失败与爆破"""
        files = self._collect_files(SERVICES_BRUTE_FORCE_CONFIG.get("redis_log_paths", []))
        if not files:
            return False

        all_lines = []
        for f in files:
            all_lines.extend(self._read_recent_lines(f, max_lines=4000))

        p_redis = re.compile(r"(?:Bad password|Authentication failure) from client:\s*([0-9a-fA-F\.:]+)")
        fails = []
        ip_counter = Counter()

        for line in reversed(all_lines):
            m = p_redis.search(line)
            if m:
                raw_ip = m.group(1)
                ip = raw_ip.split(":")[0] if ":" in raw_ip and not raw_ip.startswith("::") else raw_ip
                t_str = self._extract_timestamp(line)
                fails.append({"time": t_str, "ip": ip, "is_external": not is_private_ip(ip)})
                ip_counter[ip] += 1

        total = len(fails)
        top_ips = ip_counter.most_common(5)

        if total > 0:
            severity = Severity.HIGH if total >= 10 else Severity.MEDIUM
            title = f"检测到 Redis 缓存服务认证爆破/探测尝试 (共 {total} 次)"
            evidence_parts = [
                f"=== Redis 认证失败统计 ===",
                f"累计检测到未授权/密码错误次数: {total} 次",
            ]
            if top_ips:
                evidence_parts.append("Top 攻击源 IP:")
                for ip, cnt in top_ips:
                    ext = "外部公网⚠️" if not is_private_ip(ip) else "内网"
                    evidence_parts.append(f"  - {ip}: {cnt} 次 ({ext})")

            evidence_parts.append(f"\n=== 最近 Redis 认证失败流水 (显示最近 10 条) ===")
            for idx, item in enumerate(fails[:10], start=1):
                ext = "外部公网⚠️" if item["is_external"] else "内网"
                evidence_parts.append(f"[{idx:02d}] 时间: {item['time']} | 来源: {item['ip']} ({ext}) | 结果: Bad password / Auth failure")

            self.add_finding(
                title=title,
                severity=severity,
                description=f"在 Redis 服务日志中检测到高频的未授权访问或密码认证错误（共 {total} 次），存在遭受外部扫描爆破风险！",
                detail={"total_fails": total, "top_ips": top_ips},
                suggestion=(
                    "1. 绝不允许 Redis 监听在 0.0.0.0 (修改 redis.conf 配置 bind 127.0.0.1)；\n"
                    "2. 开启 requirepass 配置强密码（至少 20 位随机混合字符串）；\n"
                    "3. 禁用高危管理命令 (rename-command FLUSHALL \"\" 与 rename-command CONFIG \"\")。"
                ),
                raw_evidence="\n".join(evidence_parts)
            )
        else:
            self.add_finding(
                title="Redis 缓存服务认证安全审计 (未检测到爆破尝试)",
                severity=Severity.INFO,
                description="已成功读取 Redis 日志，未发现外部针对 Redis 认证口令的爆破尝试或认证失败记录。",
                raw_evidence="Redis 日志中未检测到 Bad password 或未授权访问事件。"
            )
        return True

    def _check_web_bruteforce(self) -> bool:
        """排查 Web (Nginx / Apache) 登录爆破与高频敏感路径扫描"""
        files = self._collect_files(SERVICES_BRUTE_FORCE_CONFIG.get("web_log_paths", []), max_files=4)
        if not files:
            return False

        all_lines = []
        for f in files:
            all_lines.extend(self._read_recent_lines(f, max_lines=6000))

        p_web = re.compile(r'^([0-9a-fA-F\.:]+)\s+.*?\[(.*?)\]\s+"([A-Z]+)\s+([^\s]+)\s+HTTP/[0-9\.]+"\s+(\d{3})')
        
        web_login_counter = Counter()
        web_scan_counter = Counter()
        suspicious_samples = []

        login_keywords = ["login", "admin", "wp-login", "xmlrpc", "phpmyadmin", "signin", "auth", "token"]
        scan_keywords = [".env", ".git", ".bak", ".zip", "phpmyadmin", "swagger", "actuator", "solr", "config.inc"]

        for line in reversed(all_lines):
            m = p_web.search(line)
            if m:
                ip, t_str, method, url, status = m.group(1), m.group(2), m.group(3), m.group(4), int(m.group(5))
                url_lower = url.lower()

                # 1. 检测登录接口高频 POST 爆破
                if method == "POST" and any(k in url_lower for k in login_keywords):
                    web_login_counter[ip] += 1
                    if len(suspicious_samples) < 15:
                        suspicious_samples.append({
                            "type": "Web登录爆破", "ip": ip, "time": t_str, "method": method, "url": url, "status": status
                        })

                # 2. 检测敏感文件/路径 404/403 高频扫描
                elif status in (404, 403) and any(k in url_lower for k in scan_keywords):
                    web_scan_counter[ip] += 1
                    if len(suspicious_samples) < 15:
                        suspicious_samples.append({
                            "type": "敏感文件扫描", "ip": ip, "time": t_str, "method": method, "url": url, "status": status
                        })

        login_threshold = SERVICES_BRUTE_FORCE_CONFIG.get("web_login_threshold", 10)
        scan_threshold = SERVICES_BRUTE_FORCE_CONFIG.get("web_scan_threshold", 20)

        attacker_login_ips = [ip for ip, cnt in web_login_counter.items() if cnt >= login_threshold]
        attacker_scan_ips = [ip for ip, cnt in web_scan_counter.items() if cnt >= scan_threshold]

        if attacker_login_ips or attacker_scan_ips:
            all_attacker_ips = set(attacker_login_ips) | set(attacker_scan_ips)
            severity = Severity.HIGH if (len(attacker_login_ips) > 0 or len(attacker_scan_ips) >= 3) else Severity.MEDIUM
            title = f"检测到 Web 应用遭受外部登录爆破或敏感目录扫描 (涉及 {len(all_attacker_ips)} 个恶意源 IP)"
            
            evidence_parts = ["=== Web 外部恶意爆破与扫描统计 ==="]
            if attacker_login_ips:
                evidence_parts.append("高频登录爆破源 IP (Top):")
                for ip in attacker_login_ips[:5]:
                    evidence_parts.append(f"  - {ip}: 对登录接口发起 {web_login_counter[ip]} 次 POST 请求")
            if attacker_scan_ips:
                evidence_parts.append("敏感路径扫描源 IP (Top):")
                for ip in attacker_scan_ips[:5]:
                    evidence_parts.append(f"  - {ip}: 触发 {web_scan_counter[ip]} 次敏感路径 404/403 探测")

            evidence_parts.append("\n=== 恶意请求样本采样 ===")
            for idx, s in enumerate(suspicious_samples[:10], start=1):
                evidence_parts.append(f"[{idx:02d}] 类型: {s['type']} | 来源: {s['ip']} | 请求: {s['method']} {s['url']} -> HTTP {s['status']}")

            self.add_finding(
                title=title,
                severity=severity,
                description="在 Web 服务器访问日志中捕获到外部恶意 IP 针对登录接口的高频撞库爆破，或针对系统敏感备份配置文件的目录爬行探测。",
                detail={"login_attackers": attacker_login_ips, "scan_attackers": attacker_scan_ips},
                suggestion=(
                    "1. 为 Web 后台及重要登录接口开启验证码、双因子认证 (2FA) 或限制单 IP 请求速率；\n"
                    "2. 屏蔽对敏感文件扩展名 (.env, .git, .bak, .sql) 的访问 (配置 Nginx location 规则直接返回 403)；\n"
                    "3. 部署 Web 应用防火墙 (WAF) 或使用 Fail2ban 自动阻断高频探测 IP。"
                ),
                raw_evidence="\n".join(evidence_parts)
            )
        else:
            self.add_finding(
                title="Web 访问安全审计 (未发现高频登录爆破与目录扫描)",
                severity=Severity.INFO,
                description="已成功读取 Web 访问日志，未发现超出告警阈值的针对登录后台的自动化爆破或敏感路径集中扫描行为。",
                raw_evidence="Web 访问日志中登录请求与敏感文件探测频次在正常水位以下。"
            )
        return True

    def _check_ftp_bruteforce(self) -> bool:
        """排查 FTP 服务暴力破解"""
        files = self._collect_files(SERVICES_BRUTE_FORCE_CONFIG.get("ftp_log_paths", []))
        if not files:
            return False

        all_lines = []
        for f in files:
            all_lines.extend(self._read_recent_lines(f, max_lines=4000))

        p_ftp1 = re.compile(r'FAIL LOGIN:\s+Client\s+"([0-9a-fA-F\.:]+)"')
        p_ftp2 = re.compile(r"USER\s+([^\s]+).*?530\s+Login incorrect")
        fails = []
        ip_counter = Counter()

        for line in reversed(all_lines):
            m1 = p_ftp1.search(line)
            if m1:
                ip = m1.group(1)
                t_str = self._extract_timestamp(line)
                fails.append({"time": t_str, "ip": ip, "reason": "FAIL LOGIN"})
                ip_counter[ip] += 1
                continue
            m2 = p_ftp2.search(line)
            if m2:
                u = m2.group(1)
                t_str = self._extract_timestamp(line)
                fails.append({"time": t_str, "ip": "未知IP", "reason": f"User {u} Login incorrect"})

        total = len(fails)
        if total > 0:
            severity = Severity.HIGH if total >= 10 else Severity.MEDIUM
            title = f"检测到 FTP 服务暴力破解尝试 (共 {total} 次)"
            evidence_parts = [
                f"=== FTP 认证失败统计 ===",
                f"累计检测到 FTP 登录失败次数: {total} 次",
            ]
            for ip, cnt in ip_counter.most_common(5):
                ext = "外部公网⚠️" if not is_private_ip(ip) else "内网"
                evidence_parts.append(f"  - {ip}: {cnt} 次 ({ext})")

            self.add_finding(
                title=title,
                severity=severity,
                description=f"在 FTP 服务日志中检测到针对 FTP 账户的高频密码猜测或暴力破解（共 {total} 次）。",
                detail={"total_fails": total, "top_ips": ip_counter.most_common(5)},
                suggestion=(
                    "1. 禁用 FTP 匿名访问功能 (anonymous_enable=NO)；\n"
                    "2. 若非必须，建议停用老旧明文 FTP 协议，改用更安全的 SFTP；\n"
                    "3. 限制 FTP 服务的远程访问 IP。"
                ),
                raw_evidence="\n".join(evidence_parts)
            )
        else:
            self.add_finding(
                title="FTP 服务认证安全审计 (未检测到爆破尝试)",
                severity=Severity.INFO,
                description="已成功读取 FTP 日志，未发现针对 FTP 服务账户的口令爆破尝试。",
                raw_evidence="FTP 日志中未检测到登录失败记录。"
            )
        return True

    def _add_services_summary_finding(self):
        """若系统未部署独立 MySQL/Redis/Web/FTP 日志，给出覆盖排查汇总说明"""
        self.add_finding(
            title="应用服务爆破排查总览 (MySQL/Redis/Web/FTP)",
            severity=Severity.INFO,
            description="已自动检索系统日志候选路径，当前未检测到独立的 MySQL、Redis、Web(Nginx/Apache) 或 FTP 服务日志（当前系统可能未安装上述服务或使用容器化独立运行），未发现本地服务被爆破痕迹。",
            suggestion="如本地确实运行了上述服务，建议检查相关服务日志路径配置并确保启用了访问/错误日志记录。",
            raw_evidence="未检索到活跃的 MySQL / Redis / Web / FTP 本地日志文件。"
        )
