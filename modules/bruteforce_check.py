# -*- coding: utf-8 -*-
"""
暴力破解与登录审计模块
检测项：
1. 最近 SSH 登录失败与暴力破解报告 (统计概览 + 最近失败详细流水)
2. 最近 SSH 登录成功报告 (日志 Accepted 事件与 last pts 远程会话审计 + 公网 IP 预警)
3. 当前在线活跃登录会话审计 (who / w)
"""

import os
import re
import glob
import gzip
from collections import Counter
from typing import List, Tuple, Dict, Any
from core.base import BaseModule
from core.utils import run_cmd, read_file_safe, is_private_ip, is_root, is_darwin, is_linux
from config import Severity, BRUTE_FORCE_CONFIG

class BruteForceCheck(BaseModule):
    name = "BruteForceCheck"
    description = "SSH 登录审计与暴力破解排查"

    def run(self):
        log_lines, has_perm_denied = self._get_log_lines()
        self._check_ssh_failed_logins(log_lines, has_perm_denied)
        self._check_ssh_successful_logins(log_lines, has_perm_denied)
        self._check_current_users()
        return self.findings

    def _extract_timestamp(self, line: str) -> str:
        """从日志行中提取时间戳，规范化输出"""
        # ISO 8601: 2026-11-01T10:20:30... 或 2026-11-01 10:20:30...
        m_iso = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
        if m_iso:
            return m_iso.group(1).replace("T", " ")
        # Syslog: Nov  1 10:20:30 或 Nov 01 10:20:30
        m_syslog = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})", line)
        if m_syslog:
            return m_syslog.group(1)
        return "未知时间"

    def _get_log_lines(self) -> Tuple[List[str], bool]:
        """
        尝试读取系统认证日志，返回 (有效日志行列表, 是否遭遇权限受限)
        支持 Linux (auth.log/secure/journalctl) 与 macOS (system.log/log show)
        """
        lines: List[str] = []
        has_perm_denied = False

        # 针对 macOS 系统
        if is_darwin():
            if os.path.exists("/var/log/system.log"):
                sys_lines = read_file_safe("/var/log/system.log", max_lines=3000)
                sshd_lines = [l for l in sys_lines if "sshd" in l and not l.startswith("[Permission Denied]")]
                if sshd_lines:
                    lines.extend(sshd_lines)
            if not lines:
                # 使用完整路径调用 /usr/bin/log，规避 zsh 内置 log 命令冲突
                code, out, _ = run_cmd("/usr/bin/log show --predicate 'process == \"sshd\"' --style syslog --last 1d 2>/dev/null", timeout=6)
                if code == 0 and out.strip():
                    lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Filtering the log data") and not l.startswith("Skipping info")]
            return lines, False

        # 针对 Linux 系统
        # 1. 尝试直接从日志文件读取
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

        # 2. 如果未读取到有效行或全部权限拒绝，尝试 journalctl 兜底
        if not lines:
            code, out, _ = run_cmd("journalctl -u ssh -u sshd --no-pager -n 5000 2>/dev/null", timeout=10)
            if code == 0 and out.strip():
                lines = [l for l in out.splitlines() if l.strip()]
                has_perm_denied = False

        return lines, has_perm_denied

    def _check_ssh_failed_logins(self, log_lines: List[str], has_perm_denied: bool):
        """
        审计最近 SSH 登录失败与暴力破解记录
        默认必定在报告中呈现该项检测结果。
        """
        failed_events: List[Dict[str, Any]] = []
        failed_ip_counter = Counter()
        target_user_counter = Counter()

        # 匹配模式
        # Pattern 1: Failed password / publickey for [invalid user] <user> from <ip> port <port>
        p_failed = re.compile(
            r"Failed\s+(password|publickey)\s+for\s+(invalid user\s+)?([^\s]+)\s+from\s+([0-9a-fA-F\.:]+)(?:\s+port\s+(\d+))?"
        )
        # Pattern 2: Invalid user <user> from <ip> port <port>
        p_invalid = re.compile(
            r"Invalid user\s+([^\s]+)\s+from\s+([0-9a-fA-F\.:]+)(?:\s+port\s+(\d+))?"
        )
        # Pattern 3: PAM authentication failure; ... rhost=<ip> [user=<user>]
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
                        "time": t_str,
                        "user": user_label,
                        "ip": ip,
                        "port": port,
                        "reason": reason,
                        "is_external": not is_private_ip(ip)
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
                        "time": t_str,
                        "user": f"{user} (非法用户)",
                        "ip": ip,
                        "port": port,
                        "reason": "探测不存在的账号 (Invalid user)",
                        "is_external": not is_private_ip(ip)
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
                        "time": t_str,
                        "user": user,
                        "ip": ip,
                        "port": "-",
                        "reason": "PAM底层认证失败 (PAM failure)",
                        "is_external": not is_private_ip(ip)
                    })
                continue

        # 尝试补充 lastb (btmp) 失败记录 (Linux)
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
                                "time": time_info,
                                "user": u,
                                "ip": host_or_ip,
                                "port": "-",
                                "reason": f"登录认证失败 (lastb {tty})",
                                "is_external": not is_private_ip(host_or_ip)
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
        """
        审计最近 SSH 登录成功记录
        默认必定在报告中呈现该项检测结果。
        """
        successful_records: List[Dict[str, Any]] = []
        seen_keys = set()

        # 1. 从系统认证日志解析 Accepted 成功事件
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

        # 2. 从 last 命令中解析远程 SSH 成功会话 (pts 或具有远程客户端 IP 的会话) 作为有力补充
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

                    # 严格判定 SSH 远程会话特征，剔除本地控制台及系统伪终端：
                    # 1) Linux 下远程 SSH 均为 pts/X
                    # 2) macOS 下带有远程 IPv4/IPv6 或域名的 ttys 会话
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
