# -*- coding: utf-8 -*-
"""
报告生成与终端输出模块
支持：
1. 终端彩色可视化结果渲染
2. Markdown 完整审计报告导出
3. JSON 结构化报告导出
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any
from core.base import Finding
from core.utils import Colors, color_text, get_severity_badge, get_os_info
from config import Severity

BANNER = r"""
  ____                             ____ _               _    
 / ___|  ___ _ ____   _____ _ __  / ___| |__   ___  ___| | __
 \___ \ / _ \ '__\ \ / / _ \ '__|| |   | '_ \ / _ \/ __| |/ /
  ___) |  __/ |   \ V /  __/ |   | |___| | | |  __/ (__|   < 
 |____/ \___|_|    \_/ \___|_|    \____|_| |_|\___|\___|_|\_\
          Linux 服务器安全应急检测与后门排查工具
"""

class Reporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.os_info = get_os_info()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def print_banner(self):
        print(color_text(BANNER, Colors.CYAN))
        print(color_text("=" * 72, Colors.WHITE))
        print(f" 主机名称: {color_text(self.os_info['hostname'], Colors.BOLD)}")
        print(f" 系统版本: {self.os_info['system']} {self.os_info['release']} ({self.os_info['distro']})")
        print(f" 检测时间: {self.time_str}")
        print(color_text("=" * 72, Colors.WHITE) + "\n")

    def print_module_start(self, module_name: str, desc: str):
        print(f"[*] 正在执行检测: {color_text(desc, Colors.BOLD)} ({module_name})...")

    def print_module_results(self, findings: List[Finding]):
        if not findings:
            print(f"  {color_text('[✓] 未发现异常项', Colors.GREEN)}\n")
            return

        for f in findings:
            badge = get_severity_badge(f.severity)
            print(f"  {badge} {color_text(f.title, Colors.BOLD)}")
            print(f"    ├─ 说明: {f.description}")
            if f.suggestion:
                print(f"    ├─ 建议: {color_text(f.suggestion.replace(chr(10), ' '), Colors.YELLOW)}")
            if f.raw_evidence:
                first_line = f.raw_evidence.strip().splitlines()[0]
                more_lines = len(f.raw_evidence.strip().splitlines()) - 1
                suffix = f" ... (还有 {more_lines} 行证据，已记录至报告)" if more_lines > 0 else ""
                print(f"    └─ 证据: {first_line}{suffix}")
            print()

    def generate_summary(self, all_findings: List[Finding]) -> Dict[str, int]:
        summary = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        for f in all_findings:
            if f.severity in summary:
                summary[f.severity] += 1
        return summary

    def print_final_summary(self, all_findings: List[Finding], md_path: str, json_path: str):
        summary = self.generate_summary(all_findings)
        
        print(color_text("=" * 72, Colors.WHITE))
        print(color_text("                   安全巡检与后门排查结果汇总", Colors.BOLD))
        print(color_text("=" * 72, Colors.WHITE))
        print(f"  严重风险 [CRITICAL]: {color_text(str(summary[Severity.CRITICAL]), Colors.RED if summary[Severity.CRITICAL] > 0 else Colors.GREEN)}")
        print(f"  高危风险 [HIGH]    : {color_text(str(summary[Severity.HIGH]), Colors.RED if summary[Severity.HIGH] > 0 else Colors.GREEN)}")
        print(f"  中危风险 [MEDIUM]  : {color_text(str(summary[Severity.MEDIUM]), Colors.YELLOW if summary[Severity.MEDIUM] > 0 else Colors.GREEN)}")
        print(f"  低危风险 [LOW]     : {color_text(str(summary[Severity.LOW]), Colors.CYAN)}")
        print(f"  审计信息 [INFO]    : {color_text(str(summary[Severity.INFO]), Colors.WHITE)}")
        print(color_text("-" * 72, Colors.WHITE))

        if summary[Severity.CRITICAL] > 0 or summary[Severity.HIGH] > 0:
            print(color_text("  [!] 警告: 服务器检测到高危/严重风险后门或遭受严重攻击，请立即对照报告处置！", Colors.RED))
        elif summary[Severity.MEDIUM] > 0:
            print(color_text("  [*] 提示: 服务器存在部分安全隐患，建议及时加固修复。", Colors.YELLOW))
        else:
            print(color_text("  [✓] 良好: 未发现明显后门或严重入侵痕迹，系统状态基本安全。", Colors.GREEN))

        print(f"\n  详细报告已保存至:")
        print(f"  - Markdown: {color_text(md_path, Colors.CYAN)}")
        print(f"  - JSON    : {color_text(json_path, Colors.CYAN)}")
        print(color_text("=" * 72, Colors.WHITE) + "\n")

    def export_reports(self, all_findings: List[Finding]) -> tuple:
        """导出 Markdown 与 JSON 报告"""
        hostname = self.os_info.get("hostname", "server")
        base_filename = f"security_report_{hostname}_{self.timestamp}"
        
        md_path = os.path.join(self.output_dir, f"{base_filename}.md")
        json_path = os.path.join(self.output_dir, f"{base_filename}.json")

        summary = self.generate_summary(all_findings)

        # 1. 导出 JSON
        report_data = {
            "meta": {
                "hostname": self.os_info["hostname"],
                "system": self.os_info["system"],
                "release": self.os_info["release"],
                "distro": self.os_info["distro"],
                "check_time": self.time_str,
                "summary": summary
            },
            "findings": [f.to_dict() for f in all_findings]
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

        # 2. 导出 Markdown
        md_lines = [
            f"# 服务器安全应急检测与后门排查报告",
            f"",
            f"- **主机名**: `{self.os_info['hostname']}`",
            f"- **系统信息**: `{self.os_info['system']} {self.os_info['release']} ({self.os_info['distro']})`",
            f"- **检测时间**: `{self.time_str}`",
            f"",
            f"## 一、安全风险统计概览",
            f"",
            f"| 风险等级 | 发现数量 | 说明 |",
            f"| :--- | :--- | :--- |",
            f"| **CRITICAL** (严重) | **{summary[Severity.CRITICAL]}** | 发现非root的UID 0账号、动态库劫持、已知挖矿木马或反弹Shell |",
            f"| **HIGH** (高危) | **{summary[Severity.HIGH]}** | 遭受严重SSH爆破、恶意定时任务、临时目录执行木马、异常提权文件等 |",
            f"| **MEDIUM** (中危) | **{summary[Severity.MEDIUM]}** | 异常公网成功登录、高CPU占用、系统命令近期修改等 |",
            f"| **LOW** (低危) | **{summary[Severity.LOW]}** | 少量登录失败、开机自启脚本存在自定义项等 |",
            f"| **INFO** (信息) | **{summary[Severity.INFO]}** | 活跃用户、当前监听端口、公钥配置等基线信息 |",
            f"",
            f"---",
            f"",
            f"## 二、详细排查结果与修复建议",
            f"",
        ]

        # 按严重级别排序显示
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sorted_findings = sorted(all_findings, key=lambda x: severity_order.index(x.severity) if x.severity in severity_order else 99)

        if not sorted_findings:
            md_lines.append("> [!NOTE]\n> 未产生任何检测项。")
        else:
            for idx, f in enumerate(sorted_findings, start=1):
                md_lines.append(f"### {idx}. [{f.severity}] {f.title}")
                md_lines.append(f"- **排查发现**: {f.description}")
                if f.suggestion:
                    md_lines.append(f"- **处置建议**:\n```text\n{f.suggestion}\n```")
                if f.raw_evidence:
                    md_lines.append(f"- **原始证据采样**:\n```text\n{f.raw_evidence}\n```")
                md_lines.append(f"\n---\n")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))

        return md_path, json_path
