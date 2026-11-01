# -*- coding: utf-8 -*-
"""
恶意进程、挖矿木马与反弹Shell排查模块
检测项：
1. 挖矿木马黑名单关键词匹配（xmrig, kdevtmpfsi, c3pool等）
2. 异常高 CPU 占用进程排查（排查挖矿）
3. 临时敏感目录执行的进程（/tmp, /var/tmp, /dev/shm）
4. 文件已被删除仍在内存运行的进程（deleted 隐蔽进程）
5. 反弹 Shell 进程特征（bash -i, nc -e, python pty.spawn 等）
"""

import os
import re
from core.base import BaseModule
from core.utils import run_cmd
from config import Severity, MALICIOUS_PROCESS_KEYWORDS, SUSPICIOUS_EXEC_PATHS

class ProcessCheck(BaseModule):
    name = "ProcessCheck"
    description = "恶意进程与后门反弹Shell排查"

    def run(self):
        processes = self._get_all_processes()
        self._check_malicious_keywords(processes)
        self._check_reverse_shell_processes(processes)
        self._check_suspicious_path_processes(processes)
        self._check_deleted_exe_processes()
        self._check_high_cpu_processes(processes)
        return self.findings

    def _get_all_processes(self):
        """获取系统当前全部运行中的进程列表 (ps aux)"""
        procs = []
        code, out, _ = run_cmd("ps aux", timeout=10)
        if code != 0 or not out:
            return procs

        lines = out.strip().splitlines()
        if len(lines) <= 1:
            return procs

        header = lines[0].split()
        for line in lines[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try:
                    procs.append({
                        "user": parts[0],
                        "pid": parts[1],
                        "cpu": float(parts[2]),
                        "mem": float(parts[3]),
                        "vsz": parts[4],
                        "rss": parts[5],
                        "tty": parts[6],
                        "stat": parts[7],
                        "start": parts[8],
                        "time": parts[9],
                        "command": parts[10],
                    })
                except Exception:
                    continue
        return procs

    def _check_malicious_keywords(self, processes):
        """检查包含恶意/挖矿关键字的进程（采用单词边界精确匹配，防止误伤合法进程路径）"""
        kw_regexes = [
            (kw, re.compile(r"(?:^|[^a-zA-Z0-9_-])" + re.escape(kw) + r"(?:$|[^a-zA-Z0-9_-])", re.IGNORECASE))
            for kw in MALICIOUS_PROCESS_KEYWORDS
        ]
        matched = []
        for p in processes:
            cmd = p["command"]
            for kw, regex in kw_regexes:
                if regex.search(cmd):
                    matched.append({"keyword": kw, "proc": p})
                    break

        if matched:
            self.add_finding(
                title="发现疑似挖矿木马或恶意进程！",
                severity=Severity.CRITICAL,
                description=f"检测到 {len(matched)} 个匹配已知挖矿木马/恶意程序的特征进程！",
                detail={"matched_processes": matched},
                suggestion="1. 记录 PID 及对应可执行文件路径\n2. 立即停止并终止进程：kill -9 <PID>\n3. 检查 /proc/<PID>/exe 对应的源文件并将其删除\n4. 排查对应用户的定时任务(crontab)以防复活",
                raw_evidence="\n".join([f"PID: {m['proc']['pid']} | Keyword: {m['keyword']} | Cmd: {m['proc']['command']}" for m in matched])
            )
        else:
            self.add_finding(
                title="已知恶意/挖矿进程特征排查正常",
                severity=Severity.INFO,
                description="未发现匹配常见挖矿木马（xmrig, kdevtmpfsi, c3pool等）特征的进程。"
            )

    def _check_reverse_shell_processes(self, processes):
        """检查命令行中包含反弹 Shell 特征的进程"""
        # 常见反弹 shell 特征正则
        shell_patterns = [
            r"bash\s+-i\s+>&",
            r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+",
            r"nc\s+-[e|c]\s+",
            r"ncat\s+.*-e\s+",
            r"pty\.spawn\(",
            r"socket\.socket.*connect\(",
            r"sh\s+-i\s+>&",
            r"exec\s+5<>/dev/tcp/",
        ]
        regexes = [re.compile(p, re.IGNORECASE) for p in shell_patterns]

        matched = []
        for p in processes:
            cmd = p["command"]
            for r in regexes:
                if r.search(cmd):
                    matched.append(p)
                    break

        if matched:
            self.add_finding(
                title="发现反弹 Shell (Reverse Shell) 交互后门进程！",
                severity=Severity.CRITICAL,
                description="发现典型反弹 Shell 命令行特征，表明黑客极可能正通过该 Shell 控制服务器！",
                detail={"reverse_shells": matched},
                suggestion="立即使用 kill -9 <PID> 强制杀掉进程并断开网络排查入侵入口！",
                raw_evidence="\n".join([f"PID: {p['pid']} | User: {p['user']} | Cmd: {p['command']}" for p in matched])
            )

    def _check_suspicious_path_processes(self, processes):
        """排查从 /tmp, /dev/shm 等可疑临时目录直接启动的程序"""
        suspicious = []
        for p in processes:
            cmd = p["command"]
            for spath in SUSPICIOUS_EXEC_PATHS:
                # 检查命令首项或路径是否在临时目录中
                if cmd.startswith(spath) or f" {spath}/" in cmd:
                    suspicious.append(p)
                    break

        # 进一步通过 /proc/<pid>/exe 检查（仅在 Linux 环境有效）
        if os.path.exists("/proc"):
            for p in processes:
                pid = p["pid"]
                exe_link = f"/proc/{pid}/exe"
                try:
                    if os.path.islink(exe_link):
                        real_target = os.readlink(exe_link)
                        for spath in SUSPICIOUS_EXEC_PATHS:
                            if real_target.startswith(spath) and p not in suspicious:
                                suspicious.append(p)
                                break
                except (PermissionError, FileNotFoundError):
                    continue

        if suspicious:
            self.add_finding(
                title="发现从临时目录 (/tmp, /dev/shm) 运行的可疑进程",
                severity=Severity.HIGH,
                description=f"黑客及后门程序常在 /tmp 或 /dev/shm 等拥有全局写权限的目录释放木马并执行。发现 {len(suspicious)} 个可疑进程！",
                detail={"suspicious_processes": suspicious},
                suggestion="仔细核对这些进程是否属于合法的自动化作业，若非明确程序请立即排查其文件源并终止。",
                raw_evidence="\n".join([f"PID: {p['pid']} | Cmd: {p['command']}" for p in suspicious])
            )

    def _check_deleted_exe_processes(self):
        """排查可执行文件已被删除但进程依然存活的后门（黑客自删除免痕技巧）"""
        if not os.path.exists("/proc"):
            return

        deleted_procs = []
        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                exe_link = os.path.join("/proc", pid_dir, "exe")
                try:
                    if os.path.islink(exe_link):
                        target = os.readlink(exe_link)
                        if "(deleted)" in target:
                            # 过滤正常软件更新或常规 deleted 现象，重点关注非系统常规守护
                            cmdline_path = os.path.join("/proc", pid_dir, "cmdline")
                            cmd = ""
                            if os.path.exists(cmdline_path):
                                try:
                                    with open(cmdline_path, "r", errors="ignore") as f:
                                        cmd = f.read().replace("\x00", " ")
                                except Exception:
                                    pass
                            deleted_procs.append({"pid": pid_dir, "deleted_file": target, "cmdline": cmd})
                except (PermissionError, FileNotFoundError):
                    continue
        except Exception:
            pass

        if deleted_procs:
            self.add_finding(
                title="发现已删除文件在内存中运行 (deleted 隐蔽进程)",
                severity=Severity.HIGH,
                description=f"发现 {len(deleted_procs)} 个二进制已被删除但进程仍在执行的情况。攻击者常在运行木马后删除源文件以规避静态查杀，或软件包更新未重启。",
                detail={"deleted_processes": deleted_procs},
                suggestion="使用 lsof -p <PID> 或 dump 内存排查该进程行为；如确认非系统升级遗留，请立即终止进程并提取样本分析。",
                raw_evidence="\n".join([f"PID: {dp['pid']} | Exe: {dp['deleted_file']} | Cmd: {dp['cmdline']}" for dp in deleted_procs])
            )

    def _check_high_cpu_processes(self, processes):
        """排查 CPU 占用异常高的进程（挖矿木马通常持续占用 >80% CPU）"""
        high_cpu = [p for p in processes if p["cpu"] >= 80.0]
        if high_cpu:
            self.add_finding(
                title="发现持续高 CPU 占用进程（疑似挖矿）",
                severity=Severity.MEDIUM,
                description=f"发现 {len(high_cpu)} 个进程 CPU 占用达到 80% 以上，请核查是否为合法计算业务还是挖矿病毒占用。",
                detail={"high_cpu_processes": high_cpu},
                suggestion="对比这些高占用进程的属主与运行参数，排查是否被植入矿机。",
                raw_evidence="\n".join([f"PID: {p['pid']} | User: {p['user']} | CPU: {p['cpu']}% | Cmd: {p['command'][:100]}" for p in high_cpu])
            )
