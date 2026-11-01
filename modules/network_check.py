# -*- coding: utf-8 -*-
"""
网络连接与可疑外联排查模块
检测项：
1. 本地监听端口排查（LISTEN 端口与关联进程，检测异常监听服务）
2. 建立中的网络连接排查（ESTABLISHED 连接，排查外联 C2 与矿池）
3. 命中高危/矿池端口连接检测
4. 网卡混杂模式审计（排查网络抓包嗅探后门）
"""

import re
from core.base import BaseModule
from core.utils import run_cmd, is_private_ip
from config import Severity, SUSPICIOUS_PORTS

class NetworkCheck(BaseModule):
    name = "NetworkCheck"
    description = "网络连接与异常端口排查"

    def run(self):
        self._check_listening_ports()
        self._check_established_connections()
        self._check_promiscuous_mode()
        return self.findings

    def _get_network_sockets(self):
        """尝试使用 ss 或 netstat 获取当前全部网络连接"""
        # 优先使用 ss，次选 netstat
        code, out, _ = run_cmd("ss -antup 2>/dev/null || netstat -antup 2>/dev/null", timeout=10)
        if code != 0 or not out:
            # 降级尝试 macOS 兼容命令
            code, out, _ = run_cmd("netstat -anv 2>/dev/null || lsof -i -P -n 2>/dev/null", timeout=10)
        return out.splitlines() if out else []

    def _check_listening_ports(self):
        """排查本地正在监听的端口"""
        lines = self._get_network_sockets()
        listen_items = []
        suspicious_listens = []

        for line in lines:
            if "LISTEN" not in line and "LISTENING" not in line:
                continue

            # 提取端口号与进程信息
            # 兼容不同系统的输出格式
            # 常见格式: tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1234,fd=3))
            port_match = re.search(r"[:\.](\d+)\s+.*(?:LISTEN)", line) or re.search(r"(?:LISTEN)\s+.*[:\.](\d+)", line)
            if not port_match:
                # 尝试另一种匹配: IP:Port 出现在 LISTEN 前面
                m = re.findall(r"[:\.](\d+)", line)
                if m:
                    port = int(m[0])
                else:
                    continue
            else:
                port = int(port_match.group(1))

            listen_items.append({"port": port, "raw": line.strip()})

            if port in SUSPICIOUS_PORTS:
                suspicious_listens.append({
                    "port": port,
                    "desc": SUSPICIOUS_PORTS[port],
                    "raw": line.strip()
                })

        if suspicious_listens:
            port_desc_list = [f"{x['port']}({x['desc']})" for x in suspicious_listens]
            self.add_finding(
                title="发现高危后门/可疑监听端口！",
                severity=Severity.HIGH,
                description=f"检测到系统当前正在监听已知的高危/后门端口：{', '.join(port_desc_list)}！",
                detail={"suspicious_ports": suspicious_listens},
                suggestion="立即排查对应端口绑定的进程，阻断防火墙入站访问，或使用 kill 终止对应进程。",
                raw_evidence="\n".join([f"Port {x['port']}: {x['raw']}" for x in suspicious_listens])
            )
        else:
            self.add_finding(
                title=f"本地网络监听端口审计 (共 {len(listen_items)} 个)",
                severity=Severity.INFO,
                description=f"当前系统共有 {len(listen_items)} 个端口处于 LISTEN 状态，未发现已知后门默认监听端口。",
                detail={"listening_ports": [x["port"] for x in listen_items]}
            )

    def _check_established_connections(self):
        """排查已建立的外联连接（ESTABLISHED）"""
        lines = self._get_network_sockets()
        established_conns = []
        c2_or_pool_conns = []

        for line in lines:
            if "ESTAB" not in line and "ESTABLISHED" not in line:
                continue

            established_conns.append(line.strip())

            # 检查是否有连接到已知挖矿端口
            for p, desc in SUSPICIOUS_PORTS.items():
                if f":{p} " in line or f".{p} " in line or f":{p}\t" in line:
                    c2_or_pool_conns.append({"port": p, "desc": desc, "raw": line.strip()})

        if c2_or_pool_conns:
            self.add_finding(
                title="发现与高危/矿池端口的外联通信！",
                severity=Severity.CRITICAL,
                description=f"检测到活动中的外联连接命中恶意矿池或 C2 端口特征：{', '.join([str(c['port']) for c in c2_or_pool_conns])}！",
                detail={"suspicious_connections": c2_or_pool_conns},
                suggestion="1. 立即排查外联对端 IP\n2. 定位发起连接的进程 PID 并杀灭\n3. 在防火墙设置对端 IP 的 DROP 规则",
                raw_evidence="\n".join([c["raw"] for c in c2_or_pool_conns])
            )
        else:
            self.add_finding(
                title=f"外联网络连接审计 (共 {len(established_conns)} 条)",
                severity=Severity.INFO,
                description=f"当前存在 {len(established_conns)} 条 ESTABLISHED 状态连接，未匹配到已知矿池特征端口。",
                detail={"sample_established": established_conns[:10]}
            )

    def _check_promiscuous_mode(self):
        """检查网卡是否开启混杂模式 (PROMISC)，可能存在流量嗅探抓包"""
        code, out, _ = run_cmd("ip link 2>/dev/null || ifconfig 2>/dev/null", timeout=5)
        if code == 0 and out:
            promisc_cards = []
            for line in out.splitlines():
                if "PROMISC" in line:
                    promisc_cards.append(line.strip())

            if promisc_cards:
                self.add_finding(
                    title="检测到网卡处于混杂模式 (PROMISC)",
                    severity=Severity.MEDIUM,
                    description="网卡开启混杂模式可能用于嗅探内网敏感明文流量（如密码、Token），或者为容器网络组件正常配置，需结合实际环境确认。",
                    detail={"promisc_interfaces": promisc_cards},
                    raw_evidence="\n".join(promisc_cards),
                    suggestion="确认服务器是否部署了网络抓包软件(如 tcpdump)或特定容器网桥；若无合法业务，可能被植入了网络窃听嗅探程序。"
                )
