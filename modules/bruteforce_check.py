# -*- coding: utf-8 -*-
"""
暴力破解与登录审计模块
检测项：
1. SSH 登录失败与暴力破解统计（IP、频次、受针对账号）
2. 当前在线登录用户排查
3. 近期成功登录历史审计 (last / wtmp)
4. 近期失败登录记录审计 (lastb / btmp)
"""

import os
import re
import glob
import gzip
from collections import Counter
from core.base import BaseModule
from core.utils import run_cmd, read_file_safe, is_private_ip
from config import Severity, BRUTE_FORCE_CONFIG

class BruteForceCheck(BaseModule):
    name = "BruteForceCheck"
    description = "暴力破解与登录历史审计"

    def run(self):
        self._check_ssh_bruteforce()
        self._check_current_users()
        self._check_recent_logins()
        self._check_failed_logins()
        return self.findings

    def _get_log_lines(self):
        """尝试读取系统认证日志，支持 auth.log, secure, gzip压缩包或 journalctl"""
        lines = []
        found_file = False
        
        # 1. 尝试直接从日志文件读取
        for path_pattern in BRUTE_FORCE_CONFIG["auth_log_paths"]:
            for file_path in glob.glob(path_pattern):
                if os.path.exists(file_path):
                    found_file = True
                    try:
                        if file_path.endswith(".gz"):
                            with gzip.open(file_path, "rt", encoding="utf-8", errors="replace") as f:
                                lines.extend(f.readlines())
                        else:
                            lines.extend(read_file_safe(file_path))
                    except Exception:
                        pass
        
        # 2. 如果没有找到日志文件，或者读取为空，尝试使用 journalctl
        if not lines:
            code, out, _ = run_cmd("journalctl -u ssh -u sshd --no-pager -n 5000", timeout=10)
            if code == 0 and out:
                lines = out.splitlines()
                
        return lines

    def _check_ssh_bruteforce(self):
        """分析认证日志中的暴力破解行为"""
        lines = self._get_log_lines()
        if not lines:
            self.add_finding(
                title="未检测到 SSH 认证日志",
                severity=Severity.INFO,
                description="未在默认路径 (/var/log/auth.log, /var/log/secure) 或 journalctl 中找到认证日志，可能权限不足或系统日志服务已重构。",
                suggestion="请确保以 root 权限运行脚本，以获得读取系统安全日志的权限。"
            )
            return

        failed_ip_counter = Counter()
        target_user_counter = Counter()

        # 匹配模式
        # Pattern 1: Failed password for [invalid user] <user> from <ip> port <port>
        p1 = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?([^\s]+) from ([0-9a-fA-F\.:]+)")
        # Pattern 2: Invalid user <user> from <ip>
        p2 = re.compile(r"Invalid user ([^\s]+) from ([0-9a-fA-F\.:]+)")
        # Pattern 3: authentication failure;.*rhost=([0-9a-fA-F\.:]+)(?:.*user=([^\s]+))?
        p3 = re.compile(r"authentication failure;.*rhost=([0-9a-fA-F\.:]+)")

        total_failed_attempts = 0

        for line in lines:
            m1 = p1.search(line)
            if m1:
                user, ip = m1.group(1), m1.group(2)
                failed_ip_counter[ip] += 1
                target_user_counter[user] += 1
                total_failed_attempts += 1
                continue
            
            m2 = p2.search(line)
            if m2:
                user, ip = m2.group(1), m2.group(2)
                failed_ip_counter[ip] += 1
                target_user_counter[user] += 1
                total_failed_attempts += 1
                continue

            m3 = p3.search(line)
            if m3:
                ip = m3.group(1)
                failed_ip_counter[ip] += 1
                total_failed_attempts += 1

        # 评估爆破情况
        if total_failed_attempts == 0:
            self.add_finding(
                title="SSH 认证历史正常",
                severity=Severity.INFO,
                description="在日志记录中未发现明显的 SSH 密码尝试失败或暴力破解记录。",
                suggestion="继续保持良好安全习惯，如禁用密码登录、改用 SSH 密钥认证。"
            )
            return

        # 排序前 10 恶意 IP
        top_ips = failed_ip_counter.most_common(10)
        top_users = target_user_counter.most_common(10)
        max_single_ip_attempts = top_ips[0][1] if top_ips else 0

        # 判断危险等级
        high_threshold = BRUTE_FORCE_CONFIG["high_risk_threshold"]
        threshold = BRUTE_FORCE_CONFIG["failure_threshold"]

        if total_failed_attempts >= 100 or max_single_ip_attempts >= high_threshold:
            severity = Severity.HIGH
            desc = f"检测到服务器历史上遭受过大量的 SSH 暴力破解攻击！累计检测到 {total_failed_attempts} 次失败尝试，涉及 {len(failed_ip_counter)} 个攻击源 IP。"
        elif total_failed_attempts >= threshold:
            severity = Severity.MEDIUM
            desc = f"检测到服务器存在 SSH 认证失败记录（共 {total_failed_attempts} 次），可能存在偶发探测或暴力尝试。"
        else:
            severity = Severity.LOW
            desc = f"检测到少量 SSH 认证失败（共 {total_failed_attempts} 次），通常属于正常偶发输错密码或轻微探测。"

        detail_info = {
            "total_failed_attempts": total_failed_attempts,
            "unique_attacker_ips": len(failed_ip_counter),
            "top_attacker_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "top_targeted_users": [{"user": user, "count": count} for user, count in top_users],
        }

        evidence = "=== Top 10 攻击源 IP 频次 ===\n" + "\n".join([f"{ip}: {cnt} 次" for ip, cnt in top_ips])
        if top_users:
            evidence += "\n\n=== Top 被针对探测账号 ===\n" + "\n".join([f"{u}: {cnt} 次" for u, cnt in top_users])

        self.add_finding(
            title="检测到 SSH 暴力破解尝试",
            severity=severity,
            description=desc,
            detail=detail_info,
            suggestion="1. 修改默认 SSH 端口（22 改为高位端口）\n2. 禁用 root 远程密码登录（PermitRootLogin prohibit-password 或 no）\n3. 全面使用 SSH 密钥认证并关闭 PasswordAuthentication\n4. 安装并启用 Fail2ban 或配置防火墙白名单限制访问源",
            raw_evidence=evidence
        )

    def _check_current_users(self):
        """检查当前登录会话 (who / w)"""
        code, out, _ = run_cmd("who -u || w -h", timeout=5)
        if code == 0 and out.strip():
            lines = [l for l in out.strip().splitlines() if l.strip()]
            self.add_finding(
                title=f"当前在线活跃登录会话 ({len(lines)} 个)",
                severity=Severity.INFO,
                description=f"当前系统有 {len(lines)} 个活跃登录终端，请核对是否皆为授权管理员。",
                detail={"active_sessions": lines},
                raw_evidence=out.strip(),
                suggestion="如发现未知登录 IP 或非工作时间的终端会话，可通过 pkill -kill -t <tty> 强制踢出并更改密码。"
            )

    def _check_recent_logins(self):
        """检查近期成功登录记录 (last)"""
        limit = BRUTE_FORCE_CONFIG["last_login_limit"]
        code, out, _ = run_cmd(f"last -n {limit} -F || last -n {limit}", timeout=5)
        if code == 0 and out.strip():
            lines = out.strip().splitlines()
            # 过滤包含 reboot 或 wtmp begins 的行
            login_records = [l for l in lines if l and not l.startswith("reboot") and not l.startswith("wtmp begins")]
            
            # 检查是否有异常的外网登录
            suspicious_logins = []
            for r in login_records[:30]:
                parts = r.split()
                if len(parts) >= 3:
                    ip_candidate = parts[2]
                    # 简易匹配 IPv4
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_candidate):
                        if not is_private_ip(ip_candidate):
                            suspicious_logins.append(r)

            if suspicious_logins:
                self.add_finding(
                    title="近期存在公网 IP 成功登录记录",
                    severity=Severity.MEDIUM,
                    description=f"在 recent logins (last) 中发现来自外部公网 IP 的成功登录记录（共 {len(suspicious_logins)} 条），请排查是否为合法运维行为或已被攻陷！",
                    detail={"suspicious_records": suspicious_logins},
                    raw_evidence="\n".join(suspicious_logins[:10]),
                    suggestion="立即核实公网 IP 是否为管理员的办公网络 IP；若不是，说明密码或密钥已泄露，服务器可能已被控制！请立刻阻断并排查后续命令历史。"
                )
            else:
                self.add_finding(
                    title="近期成功登录记录审计",
                    severity=Severity.INFO,
                    description=f"已成功获取最近 {len(login_records)} 条成功登录记录，未发现明显的异常公网 IP 登录。",
                    detail={"sample_records": login_records[:5]},
                    raw_evidence="\n".join(login_records[:10])
                )

    def _check_failed_logins(self):
        """检查 btmp 失败登录记录 (lastb)"""
        code, out, _ = run_cmd("lastb -n 20", timeout=5)
        if code == 0 and out.strip():
            lines = [l for l in out.strip().splitlines() if l and not l.startswith("btmp begins")]
            if lines:
                self.add_finding(
                    title=f"检测到最近登录失败记录 (lastb 共 {len(lines)} 条)",
                    severity=Severity.LOW,
                    description="系统 btmp 日志中记录了最近的登录失败事件，表明近期有未成功的认证尝试。",
                    detail={"lastb_records": lines[:10]},
                    raw_evidence="\n".join(lines[:10]),
                    suggestion="结合 SSH 爆破检测结果，注意排查是否正在进行针对性测试。"
                )
