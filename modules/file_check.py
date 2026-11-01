# -*- coding: utf-8 -*-
"""
敏感文件、后门特征与文件完整性排查模块
检测项：
1. 敏感临时目录 (/tmp, /var/tmp, /dev/shm) 可执行文件/脚本排查
2. 异常 SUID / SGID 提权后门文件扫描
3. 系统核心命令文件近期修改痕迹排查 (/bin, /sbin, /usr/bin)
4. 隐蔽目录名称排查 (如 "...", " " 伪装隐藏文件夹)
"""

import os
import stat
import time
from core.base import BaseModule
from core.utils import run_cmd
from config import Severity, FILE_CHECK_CONFIG

class FileCheck(BaseModule):
    name = "FileCheck"
    description = "敏感文件与后门痕迹排查"

    def run(self):
        self._check_tmp_directories()
        self._check_suid_files()
        self._check_recent_modified_binaries()
        self._check_hidden_trick_folders()
        return self.findings

    def _check_tmp_directories(self):
        """排查 /tmp, /dev/shm 等目录中的可执行文件与脚本"""
        scan_dirs = FILE_CHECK_CONFIG["scan_dirs"]
        executable_files = []

        for sdir in scan_dirs:
            if not os.path.exists(sdir):
                continue
            for root, _, files in os.walk(sdir):
                for f in files:
                    fpath = os.path.join(root, f)
                    try:
                        st = os.stat(fpath)
                        # 必须是普通文件，跳过 socket、管道 FIFO、设备文件等
                        if not stat.S_ISREG(st.st_mode):
                            continue
                        # 0 字节文件通常是 lock 或标志文件，不属于恶意可执行载荷
                        if st.st_size == 0:
                            continue

                        # 过滤 socket 或 lock 命名特征
                        lower_f = f.lower()
                        if lower_f.endswith((".sock", ".lock", ".pid")):
                            continue

                        # 检查是否有执行权限，或者是以脚本后缀结尾
                        is_exec = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                        ext = os.path.splitext(f)[1].lower()
                        is_script = ext in [".sh", ".py", ".pl", ".elf", ".bin", ".so"]
                        
                        # 检查是否为 ELF 或 Mach-O 原生二进制
                        is_binary = False
                        if st.st_size >= 4:
                            try:
                                with open(fpath, "rb") as bf:
                                    magic = bf.read(4)
                                    # Linux ELF (\x7fELF) 或 macOS Mach-O (\xcf\xfa\xed\xfe / \xca\xfe\xba\xbe 等)
                                    if magic == b"\x7fELF" or magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                                        is_binary = True
                            except Exception:
                                pass

                        if (is_exec and is_script) or is_binary or (is_exec and not ext):
                            executable_files.append({
                                "path": fpath,
                                "size": st.st_size,
                                "is_binary": is_binary,
                                "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
                            })
                    except Exception:
                        continue

        if executable_files:
            # 如果有原生二进制，提高警报级别为 HIGH
            has_bin = any(x["is_binary"] for x in executable_files)
            sev = Severity.HIGH if has_bin else Severity.MEDIUM

            self.add_finding(
                title=f"临时目录发现可执行文件/脚本 (共 {len(executable_files)} 个)",
                severity=sev,
                description=f"在全局可写临时目录 ({', '.join(scan_dirs)}) 中发现了可执行文件或原生二进制！这是黑客投递恶意 Payload 的高发位置！",
                detail={"files": executable_files},
                suggestion="检查这些可执行文件是否为合法安装包遗留；若非明确软件请及时隔离并删除对应文件！",
                raw_evidence="\n".join([f"[{'BINARY' if x['is_binary'] else 'SCRIPT'}] {x['path']} ({x['size']} bytes, mtime: {x['mtime']})" for x in executable_files[:20]])
            )
        else:
            self.add_finding(
                title="临时目录可执行文件扫描正常",
                severity=Severity.INFO,
                description=f"未在敏感临时目录 ({', '.join(scan_dirs)}) 中发现 ELF 二进制或可疑执行脚本。"
            )

    def _check_suid_files(self):
        """排查敏感目录下的 SUID 提权后门程序"""
        # 重点排查 /tmp, /dev/shm, /var/tmp, /home, /opt 下的 SUID 文件
        target_dirs = "/tmp /var/tmp /dev/shm /home /opt /root"
        cmd = f"find {target_dirs} -perm -4000 -type f 2>/dev/null"
        code, out, _ = run_cmd(cmd, timeout=10)
        
        if code == 0 and out.strip():
            suid_files = out.strip().splitlines()
            self.add_finding(
                title="发现异常目录下的 SUID 提权文件！",
                severity=Severity.HIGH,
                description=f"在非系统标准路径中检测到带有 SUID 权限的文件（共 {len(suid_files)} 个）。普通用户执行此类文件将继承 root 权限，是经典后门提权手段！",
                detail={"suid_files": suid_files},
                suggestion="使用 chmod u-s <path> 剥离其 SUID 权限，并核查该文件的创建来源。",
                raw_evidence="\n".join(suid_files)
            )

    def _check_recent_modified_binaries(self):
        """排查核心系统命令近期是否被篡改（防范 Rootkit 替换系统命令）"""
        days = FILE_CHECK_CONFIG["recent_modified_days"]
        bin_dirs = " ".join([d for d in FILE_CHECK_CONFIG["system_bin_dirs"] if os.path.exists(d)])
        if not bin_dirs:
            return

        cmd = f"find {bin_dirs} -type f -mtime -{days} 2>/dev/null"
        code, out, _ = run_cmd(cmd, timeout=10)
        if code == 0 and out.strip():
            modified_bins = out.strip().splitlines()
            # 过滤正常更新或者显示提示
            self.add_finding(
                title=f"系统命令目录在近 {days} 天内有文件被修改 (共 {len(modified_bins)} 个)",
                severity=Severity.MEDIUM,
                description="系统二进制目录 (/bin, /sbin, /usr/bin 等) 近期有更新或替换记录。若近期没有做过 apt/yum 系统更新，极可能是系统命令被后门篡改劫持！",
                detail={"modified_binaries": modified_bins[:30]},
                suggestion="核对服务器是否有近期的运维升级操作记录；如无，请使用 debsums (Ubuntu/Debian) 或 rpm -Vf (CentOS) 校验文件签名及完整性。",
                raw_evidence="\n".join(modified_bins[:20])
            )
        else:
            self.add_finding(
                title=f"系统核心命令目录完整性近期正常",
                severity=Severity.INFO,
                description=f"最近 {days} 天内未发现系统 /bin, /sbin 目录下的二进制被异常修改痕迹。"
            )

    def _check_hidden_trick_folders(self):
        """排查利用空格、点号欺骗命名的特殊隐藏目录"""
        trick_paths = []
        for check_root in ["/", "/root", "/tmp", "/dev/shm"]:
            if not os.path.exists(check_root):
                continue
            try:
                for entry in os.listdir(check_root):
                    # 匹配 "...", ".. ", ". " 等障眼法文件夹
                    if entry in ["...", ".. ", ". ", "  "] or (entry.startswith("..") and len(entry) > 2):
                        full_p = os.path.join(check_root, entry)
                        trick_paths.append(full_p)
            except Exception:
                pass

        if trick_paths:
            self.add_finding(
                title="发现伪装隐藏命名的障眼法目录！",
                severity=Severity.CRITICAL,
                description=f"发现使用特殊命名（如 ... 或空格伪装）的隐形目录：{', '.join(trick_paths)}！这是黑客藏匿木马与后门工具的经典技巧！",
                detail={"trick_paths": trick_paths},
                suggestion="立即排查该目录内的文件内容，备份取证后予以清理删除！",
                raw_evidence="\n".join(trick_paths)
            )
