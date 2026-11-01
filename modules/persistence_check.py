# -*- coding: utf-8 -*-
"""
持久化驻留与自启动后门排查模块
检测项：
1. 定时任务后门排查 (/etc/crontab, /etc/cron.*, /var/spool/cron/*)
2. 动态链接库劫持后门 (/etc/ld.so.preload, 典型 Rootkit 手段)
3. 开机自启动脚本排查 (/etc/rc.local, /etc/init.d)
4. Systemd 恶意自启服务排查 (/etc/systemd/system)
5. Shell 启动环境后门劫持 (/etc/profile, ~/.bashrc 等)
"""

import os
import glob
import re
from core.base import BaseModule
from core.utils import read_file_safe
from config import Severity

class PersistenceCheck(BaseModule):
    name = "PersistenceCheck"
    description = "持久化驻留与自启后门排查"

    def run(self):
        self._check_ld_preload()
        self._check_crontabs()
        self._check_rc_local()
        self._check_systemd_services()
        self._check_shell_profiles()
        return self.findings

    def _check_ld_preload(self):
        """检查动态链接库预加载劫持 (极其关键的 Linux Rootkit 隐藏手段)"""
        preload_file = "/etc/ld.so.preload"
        if os.path.exists(preload_file):
            content = read_file_safe(preload_file)
            non_empty_lines = [l.strip() for l in content if l.strip() and not l.startswith("#")]
            if non_empty_lines:
                self.add_finding(
                    title="【严重警告】发现 /etc/ld.so.preload 动态链接库劫持！",
                    severity=Severity.CRITICAL,
                    description="发现 /etc/ld.so.preload 文件且包含动态库引用！黑客与高级 Rootkit 常借此劫持 glibc 关键系统函数（如 readdir、open、kill），实现隐形进程、隐形网络连接以及窃取管理员输入！",
                    detail={"preload_content": non_empty_lines},
                    suggestion="1. 立即备份该文件并清空其内容：> /etc/ld.so.preload\n2. 寻找并隔离里面引用的 .so 文件\n3. 警惕当前 ps/netstat 命令已被 hook，建议使用静态编译工具排查",
                    raw_evidence="\n".join(non_empty_lines)
                )
                return

        self.add_finding(
            title="/etc/ld.so.preload 检查正常",
            severity=Severity.INFO,
            description="未发现 ld.so.preload 文件或内容为空，未受此类常见底层 Rootkit 劫持。"
        )

    def _check_crontabs(self):
        """排查系统与各用户定时任务"""
        cron_paths = [
            "/etc/crontab",
            "/etc/cron.d/*",
            "/etc/cron.daily/*",
            "/etc/cron.hourly/*",
            "/etc/cron.weekly/*",
            "/etc/cron.monthly/*",
            "/var/spool/cron/*",
            "/var/spool/cron/crontabs/*",
        ]

        # 恶意定时任务常见特征
        suspicious_patterns = [
            r"curl\s+.*\|\s*(?:bash|sh)",
            r"wget\s+.*\|\s*(?:bash|sh)",
            r"curl\s+-[fsSLk]+",
            r"wget\s+-[qO]+.*http",
            r"python\s+-c\s+['\"].*import",
            r"base64\s+-d",
            r"/tmp/\S+",
            r"/dev/shm/\S+",
            r"/var/tmp/\S+",
            r"\.sh\b",
        ]
        compiled_regexes = [re.compile(p, re.IGNORECASE) for p in suspicious_patterns]

        total_crons = []
        suspicious_crons = []

        for pattern in cron_paths:
            for filepath in glob.glob(pattern):
                if not os.path.isfile(filepath):
                    continue
                lines = read_file_safe(filepath)
                for line in lines:
                    c_line = line.strip()
                    if not c_line or c_line.startswith("#"):
                        continue
                    item = {"file": filepath, "content": c_line}
                    total_crons.append(item)

                    for r in compiled_regexes:
                        if r.search(c_line):
                            suspicious_crons.append(item)
                            break

        if suspicious_crons:
            self.add_finding(
                title="发现疑似恶意持久化定时任务 (Crontab)！",
                severity=Severity.HIGH,
                description=f"在定时任务中匹配到网络远程下载执行(curl/wget|sh)、Base64解密执行或临时目录脚本执行特征（共 {len(suspicious_crons)} 条）！",
                detail={"suspicious_crontabs": suspicious_crons},
                suggestion="立即删除对应定时任务条目，并检查其指向下载的外部脚本内容，追查木马源！",
                raw_evidence="\n".join([f"[{c['file']}] {c['content']}" for c in suspicious_crons])
            )
        else:
            self.add_finding(
                title=f"定时任务排查完成 (共审计 {len(total_crons)} 条任务)",
                severity=Severity.INFO,
                description=f"已扫描全部系统及用户定时任务，未发现明显的恶意下载或混淆后门特征。",
                detail={"sample_crons": total_crons[:10]}
            )

    def _check_rc_local(self):
        """检查 /etc/rc.local 等开机自启脚本"""
        rc_files = ["/etc/rc.local", "/etc/rc.d/rc.local"]
        for rf in rc_files:
            if os.path.exists(rf):
                lines = read_file_safe(rf)
                commands = [l.strip() for l in lines if l.strip() and not l.startswith("#") and l.strip() != "exit 0"]
                if commands:
                    self.add_finding(
                        title=f"开机自启动脚本存在自定义命令: {rf}",
                        severity=Severity.LOW,
                        description=f"{rf} 中配置了开机执行指令（共 {len(commands)} 行），请核对是否皆为合法的业务启动项。",
                        detail={"commands": commands},
                        raw_evidence="\n".join(commands),
                        suggestion="如非系统必要自启脚本，建议禁用或清理未知指令。"
                    )

    def _check_systemd_services(self):
        """排查最近修改的 systemd 单元文件"""
        service_dirs = ["/etc/systemd/system"]
        suspicious_services = []

        for sdir in service_dirs:
            if not os.path.exists(sdir):
                continue
            for root, _, files in os.walk(sdir):
                for f in files:
                    if f.endswith(".service"):
                        fpath = os.path.join(root, f)
                        lines = read_file_safe(fpath)
                        for l in lines:
                            if "ExecStart=" in l:
                                # 检查是否从 /tmp 等敏感目录启动
                                if any(p in l for p in ["/tmp", "/var/tmp", "/dev/shm", "curl", "wget", "base64"]):
                                    suspicious_services.append({"file": fpath, "exec_start": l.strip()})

        if suspicious_services:
            self.add_finding(
                title="发现可疑 Systemd 自启服务配置",
                severity=Severity.HIGH,
                description=f"在 /etc/systemd/system 中发现服务单元包含异常启动路径或下载指令（共 {len(suspicious_services)} 个）！",
                detail={"suspicious_services": suspicious_services},
                suggestion="使用 systemctl stop <service> && systemctl disable <service> 停用并删除该服务文件。",
                raw_evidence="\n".join([f"[{s['file']}] {s['exec_start']}" for s in suspicious_services])
            )

    def _check_shell_profiles(self):
        """排查 Shell 全局与用户环境变量配置文件中的异常命令"""
        profile_targets = [
            "/etc/profile",
            "/etc/bash.bashrc",
            "/root/.bashrc",
            "/root/.bash_profile",
            "/root/.profile",
        ]
        # 匹配非正常的网络外联命令或隐藏 alias
        suspicious_in_profile = []
        for pfile in profile_targets:
            if os.path.isfile(pfile):
                lines = read_file_safe(pfile)
                for l in lines:
                    cl = l.strip()
                    if not cl or cl.startswith("#"):
                        continue
                    if any(kw in cl for kw in ["curl ", "wget ", "alias sudo=", "export LD_PRELOAD", "/dev/tcp"]):
                        suspicious_in_profile.append({"file": pfile, "line": cl})

        if suspicious_in_profile:
            self.add_finding(
                title="发现 Shell 配置文件被篡改/植入可疑指令！",
                severity=Severity.HIGH,
                description=f"在 Shell 环境初始化脚本（.bashrc / profile）中检测到网络请求、sudo别名劫持或LD_PRELOAD修改指令！",
                detail={"profile_items": suspicious_in_profile},
                suggestion="管理员每次登录 Shell 都会无意触发这些代码！请立即编辑清除恶意注入语句。",
                raw_evidence="\n".join([f"[{x['file']}] {x['line']}" for x in suspicious_in_profile])
            )
