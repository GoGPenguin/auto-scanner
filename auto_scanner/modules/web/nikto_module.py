#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import json
import os
from ..base_module import BaseModule

class NiktoModule(BaseModule):
    name = "Nikto"
    tag = "web"

    def pre_run_check(self, target, profile):
        return bool(target.web_urls)

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_find = []
        for url in target.web_urls:
            safe = url.replace("/", "")
            outfile = f"{target.project_dir}/nikto_{safe}_{timestamp}.json"
            cmd = ['nikto', '-h', url, '-o', outfile, '-Format', 'json']
            if tool_args: cmd.extend(tool_args.split())

            try:
                subprocess.run(cmd, timeout=default_timeout or 1800, capture_output=True)
                if os.path.exists(outfile):
                    with open(outfile) as f:
                        data = json.load(f)
                        if 'vulnerabilities' in data:
                            for v in data['vulnerabilities']:
                                msg = f"{v.get('method')} {v.get('url')} - {v.get('msg')}"
                                all_find.append(msg)
                                target.add_json_result({
                                    "tool": "Nikto", "url": url, 
                                    "msg": v.get('msg'), "id": v.get('id')
                                })
            except Exception as e: all_find.append(f"[ERR] {url}: {e}")
        target.add_result(self.name, all_find)