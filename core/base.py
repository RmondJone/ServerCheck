# -*- coding: utf-8 -*-
"""
核心基础类定义
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from config import Severity

class Finding:
    """单个检测发现的问题/安全项"""
    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        detail: Optional[Any] = None,
        suggestion: str = "",
        raw_evidence: str = ""
    ):
        self.title = title
        self.severity = severity
        self.description = description
        self.detail = detail
        self.suggestion = suggestion
        self.raw_evidence = raw_evidence
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "detail": self.detail,
            "suggestion": self.suggestion,
            "raw_evidence": self.raw_evidence,
            "timestamp": self.timestamp,
        }


class BaseModule:
    """检测模块基类"""
    name: str = "BaseModule"
    description: str = "基础检测模块"

    def __init__(self):
        self.findings: List[Finding] = []

    def add_finding(
        self,
        title: str,
        severity: str,
        description: str,
        detail: Optional[Any] = None,
        suggestion: str = "",
        raw_evidence: str = ""
    ):
        finding = Finding(
            title=title,
            severity=severity,
            description=description,
            detail=detail,
            suggestion=suggestion,
            raw_evidence=raw_evidence
        )
        self.findings.append(finding)

    def run(self) -> List[Finding]:
        """子类必须实现的检测逻辑"""
        raise NotImplementedError("Subclasses must implement run()")

    def get_summary(self) -> Dict[str, int]:
        """统计该模块各级别告警数量"""
        summary = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        for f in self.findings:
            if f.severity in summary:
                summary[f.severity] += 1
        return summary
