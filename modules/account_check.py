# -*- coding: utf-8 -*-
"""
账号安全与后门账号审计模块
检测项：
1. 特权用户审计（检查 UID=0 的非 root 账号，极高危后门）
2. 空口令及弱状态账户排查 (/etc/shadow)
3. 拥有登录 Shell (如 /bin/bash, /bin/sh) 的用户列表
4. Sudo 提权配置审计 (/etc/sudoers, /etc/sudoers.d) 是否存在 NOPASSWD: ALL
5. SSH 授权公钥排查 (~/.ssh/authorized_keys) 是否存在后门免密公钥
"""

import os
import glob
import re
from core.base import BaseModule
from core.utils import run_cmd, read_file_safe, is_root, is_darwin
from config import Severity

class AccountCheck(BaseModule):
    name = "AccountCheck"
    description = "系统账号安全与后门账号审计"

    def run(self):
        self._check_uid_zero_users()
        self._check_empty_passwords()
        self._check_loginable_users()
        self._check_sudoers_privileges()
        self._check_authorized_keys()
        return self.findings

    def _check_uid_zero_users(self):
        """检查 UID 为 0 的用户（除 root 外）"""
        passwd_lines = read_file_safe("/etc/passwd")
        uid_zero_users = []
        for line in passwd_lines:
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                username = parts[0]
                uid = parts[2]
                if uid == "0" and username != "root":
                    uid_zero_users.append(username)

        if uid_zero_users:
            self.add_finding(
                title="发现异常 UID 0 特权后门账户！",
                severity=Severity.CRITICAL,
                description=f"发现非 root 用户的 UID 被设置为 0：{', '.join(uid_zero_users)}！这是极其典型的黑客后门提权手法，具有与 root 相同的最高权限！",
                detail={"malicious_accounts": uid_zero_users},
                suggestion="立即删除或锁定此用户账号！命令：`userdel -f <username>`，并全面排查该账号的创建时间和操作日志。",
                raw_evidence="\n".join([l for l in passwd_lines if any(u in l for u in uid_zero_users)])
            )
        else:
            self.add_finding(
                title="特权用户 UID 0 审计正常",
                severity=Severity.INFO,
                description="系统中只有 root 用户的 UID 为 0，未发现伪装特权账号。"
            )

    def _check_empty_passwords(self):
        """检查是否存在空口令账号"""
        if is_darwin():
            self.add_finding(
                title="当前系统 (macOS) 无 /etc/shadow 文件",
                severity=Severity.INFO,
                description="macOS 采用 OpenDirectory 框架管理账户与凭据，不使用 /etc/shadow 文件，已自动跳过 Shadow 文本审计。"
            )
            return

        shadow_path = "/etc/shadow"
        if not os.path.exists(shadow_path):
            self.add_finding(
                title="系统未检测到 /etc/shadow 文件",
                severity=Severity.INFO,
                description="系统中不存在 /etc/shadow 文件，可能采用网络目录认证 (LDAP/AD/PAM) 或非传统 Linux 发行版。"
            )
            return

        shadow_lines = read_file_safe(shadow_path)
        if not shadow_lines or (shadow_lines and "Permission Denied" in shadow_lines[0]):
            if not is_root():
                self.add_finding(
                    title="权限不足，无法读取 /etc/shadow",
                    severity=Severity.INFO,
                    description="读取 /etc/shadow 需要超级管理员权限（root）。当前为普通用户运行，空口令检测已跳过。",
                    suggestion="请使用 sudo 重新运行脚本以获取完整审计能力。"
                )
            else:
                self.add_finding(
                    title="无法读取 /etc/shadow",
                    severity=Severity.INFO,
                    description="当前已为 root 权限，但读取 /etc/shadow 失败，可能受 SELinux/AppArmor 等访问控制模块限制。"
                )
            return

        empty_pass_users = []
        for line in shadow_lines:
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                username = parts[0]
                password_hash = parts[1]
                # 空密码：长度为0，或者非锁定(!/!!/x/*)但为空
                if password_hash == "" or password_hash == "::":
                    empty_pass_users.append(username)

        if empty_pass_users:
            self.add_finding(
                title="发现空口令账户！",
                severity=Severity.CRITICAL,
                description=f"以下用户没有设置密码，任何人都可无密登录：{', '.join(empty_pass_users)}！",
                detail={"empty_password_accounts": empty_pass_users},
                suggestion="立即为这些账户设置强密码（`passwd <username>`）或者锁定账户（`passwd -l <username>`）。",
                raw_evidence="Empty password found for: " + ", ".join(empty_pass_users)
            )
        else:
            self.add_finding(
                title="/etc/shadow 口令状态审计正常",
                severity=Severity.INFO,
                description="已成功审计 /etc/shadow，未发现空口令账户。"
            )

    def _check_loginable_users(self):
        """检查拥有可用登录 Shell 的用户列表"""
        passwd_lines = read_file_safe("/etc/passwd")
        non_login_shells = ["/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false"]
        login_users = []

        for line in passwd_lines:
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 7:
                username = parts[0]
                shell = parts[6].strip()
                if shell and shell not in non_login_shells:
                    login_users.append({"username": username, "shell": shell, "uid": parts[2]})

        system_like_users_with_shell = []
        for u in login_users:
            # 常见本不应该有登录 shell 的系统账号
            if u["username"] in ["daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "systemd-network", "apache", "nginx", "mysql", "redis"]:
                system_like_users_with_shell.append(u)

        if system_like_users_with_shell:
            self.add_finding(
                title="系统/服务账号异常拥有登录 Shell",
                severity=Severity.HIGH,
                description=f"检测到常见系统/服务账号被分配了解释器交互式 Shell：{', '.join([x['username'] for x in system_like_users_with_shell])}，存在被后门滥用风险！",
                detail={"suspicious_users": system_like_users_with_shell},
                suggestion="修改其登录 Shell 为 nologin：`usermod -s /usr/sbin/nologin <username>`",
                raw_evidence=str(system_like_users_with_shell)
            )
        else:
            self.add_finding(
                title=f"系统可登录用户审计 (共 {len(login_users)} 个)",
                severity=Severity.INFO,
                description=f"当前系统中配置了有效登录 Shell 的用户共 {len(login_users)} 个：{', '.join([x['username'] for x in login_users])}。",
                detail={"login_users": login_users}
            )

    def _check_sudoers_privileges(self):
        """检查 sudoers 是否有危险的免密无限制提权"""
        sudoer_files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
        dangerous_rules = []

        for fpath in sudoer_files:
            if not os.path.isfile(fpath):
                continue
            lines = read_file_safe(fpath)
            for line in lines:
                clean_l = line.strip()
                if not clean_l or clean_l.startswith("#"):
                    continue
                # 检查是否存在针对所有命令的免密完全提权 (NOPASSWD: ALL)
                # 需区分限制在特定二进制命令的免密白名单（例如: ALL ALL=(ALL) NOPASSWD: /usr/local/bin/helper）
                if "NOPASSWD:" in clean_l:
                    cmd_part = clean_l.split("NOPASSWD:", 1)[1].strip()
                    cmds = [c.strip() for c in cmd_part.split(",")]
                    # 匹配命令列表中直接为 ALL 或以 ALL 结尾通配任意命令的危险规则
                    if any(re.search(r"^\s*ALL\b", c) for c in cmds):
                        dangerous_rules.append({"file": fpath, "rule": clean_l})

        if dangerous_rules:
            self.add_finding(
                title="发现免密完全 Sudo 提权配置 (NOPASSWD: ALL)",
                severity=Severity.HIGH,
                description="发现 sudoers 文件中存在 NOPASSWD: ALL 免密码完全提权规则，如果该账号被攻陷，攻击者无需口令即可瞬间执行任意命令获取 root 权限！",
                detail={"dangerous_rules": dangerous_rules},
                suggestion="评估这些规则的必要性，尽量限制特定执行命令白名单，或移除 NOPASSWD: ALL 设置。",
                raw_evidence="\n".join([f"{d['file']}: {d['rule']}" for d in dangerous_rules])
            )
        else:
            self.add_finding(
                title="Sudo 免密完全提权审计正常",
                severity=Severity.INFO,
                description="未发现 NOPASSWD: ALL 无限制任意命令免密超级提权配置。"
            )

    def _check_authorized_keys(self):
        """排查所有用户目录下的 authorized_keys 公钥"""
        key_files = (
            glob.glob("/root/.ssh/authorized_keys*") +
            glob.glob("/home/*/.ssh/authorized_keys*") +
            glob.glob("/Users/*/.ssh/authorized_keys*") +
            glob.glob("/var/root/.ssh/authorized_keys*")
        )
        found_keys = []

        for kf in key_files:
            if os.path.isfile(kf):
                lines = read_file_safe(kf)
                for l in lines:
                    cl = l.strip()
                    if cl and not cl.startswith("#"):
                        found_keys.append({"file": kf, "key_preview": cl[:60] + "..." + cl[-20:] if len(cl) > 80 else cl})

        if found_keys:
            self.add_finding(
                title=f"已配置 SSH 免密公钥审计 (共 {len(found_keys)} 条)",
                severity=Severity.INFO,
                description=f"在用户的 .ssh/authorized_keys 中发现 {len(found_keys)} 个配置的公钥。请管理员务必逐一核实这些公钥是否均为已知受信任的运维终端！",
                detail={"keys": found_keys},
                raw_evidence="\n".join([f"[{k['file']}] {k['key_preview']}" for k in found_keys]),
                suggestion="黑客常在入侵后将自己的公钥悄悄追加至 authorized_keys 维持持久化访问，如发现未知注释（如未知邮箱、未知别名）的公钥，应立即清理！"
            )
