# -*- coding: utf-8 -*-
"""
系统操作与通用辅助函数
"""

import os
import sys
import subprocess
import platform
import re
import ipaddress
from typing import Tuple, List, Optional, Dict

class Colors:
    """终端彩色控制码"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # 告警等级对应颜色
    SEVERITY_COLORS = {
        "CRITICAL": "\033[1;31m",  # 亮红/粗体红
        "HIGH": "\033[31m",        # 红色
        "MEDIUM": "\033[33m",      # 黄色
        "LOW": "\033[36m",         # 青色
        "INFO": "\033[32m",        # 绿色
    }

def color_text(text: str, color: str) -> str:
    """包装终端彩色字符串"""
    return f"{color}{text}{Colors.RESET}"

def get_severity_badge(severity: str) -> str:
    """获取带颜色的等级徽章"""
    c = Colors.SEVERITY_COLORS.get(severity, Colors.WHITE)
    return f"{c}[{severity:^8}]{Colors.RESET}"

def is_root() -> bool:
    """检查当前是否以 root / 超级用户权限运行"""
    try:
        return os.geteuid() == 0
    except AttributeError:
        # 非 Unix 系统
        return False

def is_darwin() -> bool:
    """判断当前系统是否为 macOS (Darwin)"""
    return platform.system().lower() == "darwin"

def is_linux() -> bool:
    """判断当前系统是否为 Linux"""
    return platform.system().lower() == "linux"

def get_os_info() -> Dict[str, str]:
    """获取操作系统基本信息"""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
        "distro": "Unknown",
    }
    
    # 读取 macOS 版本
    if info["system"] == "Darwin":
        mac_ver = platform.mac_ver()[0]
        info["distro"] = f"macOS {mac_ver}" if mac_ver else "macOS"
    # 读取 Linux 发行版详情
    elif os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        info["distro"] = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass
    elif os.path.exists("/etc/redhat-release"):
        try:
            with open("/etc/redhat-release", "r", encoding="utf-8", errors="ignore") as f:
                info["distro"] = f.read().strip()
        except Exception:
            pass
            
    return info

def run_cmd(cmd: str, timeout: int = 15) -> Tuple[int, str, str]:
    """
    安全执行系统命令
    返回: (returncode, stdout, stderr)
    """
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return -1, "", str(e)

def read_file_safe(path: str, max_lines: Optional[int] = None) -> List[str]:
    """安全读取文件内容，返回行列表"""
    if not os.path.exists(path) or not os.path.isfile(path):
        return []
    
    lines = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if max_lines and i >= max_lines:
                    break
                lines.append(line.rstrip("\r\n"))
    except PermissionError:
        return [f"[Permission Denied] 无法读取文件: {path}"]
    except Exception as e:
        return [f"[Error] 读取文件失败 {path}: {str(e)}"]
        
    return lines

def is_private_ip(ip: str) -> bool:
    """判断是否为内网/本地私有/保留 IP，支持 IPv4 与 IPv6"""
    if not ip or ip in ("127.0.0.1", "::1", "0.0.0.0", "*", "localhost"):
        return True
    clean_ip = ip.strip("[]")
    if clean_ip.startswith("::ffff:"):
        clean_ip = clean_ip[7:]
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        return (
            ip_obj.is_loopback or 
            ip_obj.is_link_local or 
            (isinstance(ip_obj, ipaddress.IPv4Address) and (
                ip_obj in ipaddress.IPv4Network("10.0.0.0/8") or
                ip_obj in ipaddress.IPv4Network("172.16.0.0/12") or
                ip_obj in ipaddress.IPv4Network("192.168.0.0/16")
            )) or
            (isinstance(ip_obj, ipaddress.IPv6Address) and (
                ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            ))
        )
    except ValueError:
        return True
