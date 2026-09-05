from __future__ import annotations

import warnings
from pathlib import Path

import pandas as pd


def _excel_engine() -> str:
    """优先用 python-calamine（Rust 实现，xlsx 读取快 5 倍+），缺失时回退 openpyxl。"""
    try:
        import python_calamine  # noqa: F401

        return "calamine"
    except ImportError:
        return "openpyxl"


def read_export_excel(path: str | Path, *, skiprows: int = 7, usecols=None) -> pd.DataFrame:
    """读取 SIP 导出 xlsx（默认跳过前 7 行填充空行），自动选择最快可用引擎。"""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Workbook contains no default style")
        return pd.read_excel(Path(path), engine=_excel_engine(), skiprows=skiprows, usecols=usecols)
