#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
from ..base_module import BaseModule

class Wafw00fModule(BaseModule):
    name = "WAFW00F"
    tag = "web"
    def pre_run_check(self, target, profile): return bool(target.web_urls)
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_res = []
        for url in target.web_urls:
            cmd = ['wafw00f', url]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=default_timeout or 120)
                all_res.append(f"--- {url} ---\n{res.stdout}")
                target.add_json_result({"tool": "WAFW00F", "url": url, "output": res.stdout})
            except Exception as e: all_res.append(f"[ERR] {e}")
        target.add_result(self.name, all_res)