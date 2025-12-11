#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import json
import os
from ..base_module import BaseModule

class WhatWebModule(BaseModule):
    name = "WhatWeb"
    tag = "web"

    def pre_run_check(self, target, profile): return bool(target.web_urls)

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_find = []
        for url in target.web_urls:
            outfile = f"{target.project_dir}/whatweb_{timestamp}.json"
            cmd = ['whatweb', f'--log-json={outfile}', '-a', '3', url]
            if tool_args: cmd.extend(tool_args.split())

            try:
                subprocess.run(cmd, timeout=default_timeout or 300, capture_output=True)
                if os.path.exists(outfile):
                    with open(outfile) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for d in data:
                                all_find.append(f"Target: {d.get('target')}")
                                target.add_json_result({"tool": "WhatWeb", "data": d})
            except Exception as e: all_find.append(f"[ERR] {e}")
        target.add_result(self.name, all_find)