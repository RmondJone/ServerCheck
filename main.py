#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux 服务器后门检测与爆破历史排查主程序
用法：
  sudo python3 main.py
"""

import sys
import argparse
from typing import List

from core.reporter import Reporter
from core.utils import is_root, color_text, Colors
from core.base import Finding
from modules.bruteforce_check import BruteForceCheck
from modules.account_check import AccountCheck
from modules.process_check import ProcessCheck
from modules.network_check import NetworkCheck
from modules.persistence_check import PersistenceCheck
from modules.file_check import FileCheck

def parse_args():
    parser = argparse.ArgumentParser(
        description="Linux 服务器安全应急检测与后门排查工具",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-m", "--module",
        type=str,
        choices=["bruteforce", "account", "process", "network", "persistence", "file"],
        help="指定仅执行某个检测模块：\n"
             "  bruteforce  - 暴力破解与登录历史审计\n"
             "  account     - 账号安全与后门账户排查\n"
             "  process     - 挖矿木马与反弹Shell排查\n"
             "  network     - 异常网络连接与端口排查\n"
             "  persistence - 定时任务与持久化后门排查\n"
             "  file        - 敏感文件与提权后门排查"
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default="reports",
        help="指定报告输出目录 (默认为当前工程下的 reports/ 目录)"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    reporter = Reporter(output_dir=args.output_dir)
    reporter.print_banner()

    # 检查运行权限
    if not is_root():
        print(color_text("[!] 提示: 当前未以 root / sudo 权限运行。", Colors.YELLOW))
        print(color_text("    部分涉及安全日志 (/var/log/auth.log, /var/log/secure)、密码影子文件 (/etc/shadow)", Colors.YELLOW))
        print(color_text("    以及受限进程/网络连接信息的检测项可能会因权限受限而跳过或数据不全。", Colors.YELLOW))
        print(color_text("    如需获得最全面的排查能力，强烈建议使用: sudo python3 main.py\n", Colors.YELLOW))

    all_modules = [
        ("bruteforce", BruteForceCheck()),
        ("account", AccountCheck()),
        ("process", ProcessCheck()),
        ("network", NetworkCheck()),
        ("persistence", PersistenceCheck()),
        ("file", FileCheck()),
    ]

    # 根据参数筛选模块
    modules_to_run = all_modules
    if args.module:
        modules_to_run = [m for m in all_modules if m[0] == args.module]

    all_findings: List[Finding] = []

    for mod_key, mod_instance in modules_to_run:
        reporter.print_module_start(mod_instance.name, mod_instance.description)
        try:
            findings = mod_instance.run()
            all_findings.extend(findings)
            reporter.print_module_results(findings)
        except Exception as e:
            print(f"  {color_text(f'[!] 模块 {mod_instance.name} 执行出错: {str(e)}', Colors.RED)}\n")

    # 导出报告并打印最终总结
    md_path, json_path = reporter.export_reports(all_findings)
    reporter.print_final_summary(all_findings, md_path, json_path)

if __name__ == "__main__":
    main()
