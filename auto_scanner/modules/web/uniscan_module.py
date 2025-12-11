#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
from ..base_module import BaseModule

class UniscanModule(BaseModule):
    name = "Uniscan"
    tag = "web"
    def pre_run_check(self, target, profile): return target.web_urls and profile == 'detailed'
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_res = []
        for url in target.web_urls:
            cmd = ['uniscan', '-u', url, '-qwe']
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=default_timeout or 600)
                all_res.append(res.stdout)
                target.add_json_result({"tool": "Uniscan", "url": url, "log": res.stdout})
            except Exception as e: all_res.append(f"[ERR] {e}")
        target.add_result(self.name, all_res)