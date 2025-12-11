#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
from ..base_module import BaseModule

class SslScanModule(BaseModule):
    name = "SSLScan"
    tag = "network"

    def pre_run_check(self, target, profile):
        return bool(target.ssl_ports) and bool(target.ip)

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_res = []
        for port in target.ssl_ports:
            cmd = ['sslscan', f"{target.ip}:{port}"]
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=default_timeout or 300)
                all_res.append(f"--- Port {port} ---\n{res.stdout}")
                target.add_json_result({"tool": "SSLScan", "port": port, "output": res.stdout})
            except Exception as e: all_res.append(f"[ERR] {e}")
        target.add_result(self.name, all_res)