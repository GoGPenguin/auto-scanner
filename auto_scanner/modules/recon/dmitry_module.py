#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
from ..base_module import BaseModule

class DmitryModule(BaseModule):
    name = "Dmitry"
    tag = "recon"
    
    def pre_run_check(self, target, profile):
        return not target.target_str.replace('.', '').isdigit()

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        outfile = f"{target.project_dir}/dmitry_{timestamp}"
        cmd = ['dmitry']
        if tool_args: cmd.extend(tool_args.split())
        else: cmd.extend(['-o', outfile, target.target_str])
        
        try:
            subprocess.run(cmd, timeout=default_timeout or 300, capture_output=True)
            # Parse đơn giản
            try:
                with open(f"{outfile}.txt") as f: content = f.read()
                target.add_result(self.name, ["  [+] Xem chi tiết trong file report."])
                target.add_json_result({"tool": "Dmitry", "content": content})
            except: pass
        except Exception as e:
            target.add_result(self.name, [f"[ERR] {e}"])