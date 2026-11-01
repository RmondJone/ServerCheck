# -*- coding: utf-8 -*-
"""
安全检测全局配置
"""

import os

# 危险等级定义
class Severity:
    CRITICAL = "CRITICAL"  # 严重危险 (如: UID 0非root账户, ld.so.preload被劫持, 挖矿进程运行, 反弹Shell)
    HIGH = "HIGH"          # 高危风险 (如: 遭受严重爆破, 可疑自启脚本, /tmp目录运行未知程序)
    MEDIUM = "MEDIUM"      # 中危隐患 (如: 空口令账户, 存在密码失效策略问题, 开放高危远程端口)
    LOW = "LOW"            # 低危提示 (如: 常见日志警告, 正常服务未限制IP)
    INFO = "INFO"          # 审计信息 (如: 当前活跃用户列表, 系统基本信息)

# 暴力破解检测配置
BRUTE_FORCE_CONFIG = {
    # 爆破失败次数阈值（超过该次数判定为爆破行为）
    "failure_threshold": 10,
    # 高危爆破失败次数阈值（超过该次数判定为严重持续攻击）
    "high_risk_threshold": 50,
    # 日志文件搜索候选路径
    "auth_log_paths": [
        "/var/log/auth.log",       # Debian / Ubuntu
        "/var/log/secure",         # CentOS / RHEL / Rocky / Fedora
        "/var/log/auth.log.1",
        "/var/log/secure.1",
    ],
    # 检查最近多少条登录记录
    "last_login_limit": 50,
    # 报告中展示最近流水条数
    "recent_display_limit": 15,
}

# 挖矿木马与恶意进程黑名单特征（精确匹配或单词边界匹配）
MALICIOUS_PROCESS_KEYWORDS = [
    "xmrig", "c3pool", "minerd", "xmr-stak", "kworkerds",
    "wnTKYg", "stratum", "monero", "cpuminer", "nanopool", "supportxmr",
    "redisscan", "kinsing", "kdevtmpfsi", "anacronx", "systemdl",
    "bproot", "cryptonight", "nicehash", "minexmr"
]

# 常见后门与可疑路径（这些路径下运行可执行文件通常是高危的）
SUSPICIOUS_EXEC_PATHS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run/user",
]

# 高危端口列表（常见木马、C2回连或高危未授权访问端口）
SUSPICIOUS_PORTS = {
    3333: "Stratum 挖矿协议默认端口",
    4444: "Metasploit Meterpreter 常用反弹端口",
    5555: "常见挖矿/后门端口",
    6666: "IRC 后门常用端口",
    7777: "挖矿/后门反弹端口",
    8888: "常见后门/Web控制台",
    9999: "可疑高端口反弹 Shell",
    14444: "Cryptonight 矿池端口",
    33333: "矿池端口",
    44444: "矿池端口",
    55555: "矿池端口",
}

# 持久化后门关注目录与文件
PERSISTENCE_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/etc/ld.so.preload",
    "/etc/rc.local",
    "/etc/rc.d/rc.local",
    "/etc/init.d",
    "/etc/profile",
    "/etc/profile.d",
    "/etc/bash.bashrc",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.bash_login",
    "/root/.profile",
    "/home/*/.bashrc",
    "/home/*/.bash_profile",
]

# 敏感文件检测配置
FILE_CHECK_CONFIG = {
    # 扫描敏感目录
    "scan_dirs": ["/tmp", "/var/tmp", "/dev/shm"],
    # 查找最近 N 天内被修改过的关键目录二进制
    "recent_modified_days": 3,
    "system_bin_dirs": ["/bin", "/sbin", "/usr/bin", "/usr/sbin"],
    # 常见 webshell 关键字
    "webshell_patterns": [
        r"eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)",
        r"assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)",
        r"base64_decode\s*\(",
        r"passthru\s*\(",
        r"shell_exec\s*\(",
        r"system\s*\(",
    ],
}
