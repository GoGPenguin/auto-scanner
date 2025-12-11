#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import shutil
import os
from ..base_module import BaseModule

class SkipfishModule(BaseModule):
    name = "Skipfish"
    tag = "web"
    def pre_run_check(self, target, profile): return target.web_urls and profile == 'detailed'
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_res = []
        for url in target.web_urls:
            outdir = f"{target.project_dir}/skipfish_{timestamp}"
            if os.path.exists(outdir): shutil.rmtree(outdir)
            cmd = ['skipfish', '-o', outdir, url]
            try:
                subprocess.run(cmd, capture_output=True, timeout=default_timeout or 3600)
                msg = f"Report saved at: {outdir}/index.html"
                all_res.append(msg)
                target.add_json_result({"tool": "Skipfish", "url": url, "report": outdir})
            except Exception as e: all_res.append(f"[ERR] {e}")
        target.add_result(self.name, all_res)