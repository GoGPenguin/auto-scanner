#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import shutil 

class BaseModule:
    """
    Lớp 'Template' (Base) cho tất cả các module quét.
    (v1.5: Cập nhật hàm 'run' để nhận tool_args và default_timeout)
    """
    
    name = "Base Module"
    
    def __init__(self, engine):
        self.engine = engine

    def pre_run_check(self, target, profile):
        return True

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=1800):
        """
        (MỚI v1.5) Hàm 'run' được cập nhật
        - tool_args: Chuỗi tham số tùy chỉnh (ví dụ: "-A -T5")
        - default_timeout: Timeout chung do người dùng đặt (ví dụ: 3600)
        """
        raise NotImplementedError(f"Hàm 'run' chưa được định nghĩa trong {self.name}")