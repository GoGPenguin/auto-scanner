#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
from ..base_module import BaseModule

class GobusterModule(BaseModule):
    name = "Gobuster"
    tag = "web"

    def pre_run_check(self, target, profile):
        return bool(target.web_urls)

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_find = []
        for url in target.web_urls:
            safe = url.replace("/", "")
            outfile = f"{target.project_dir}/gobuster_{safe}_{timestamp}.txt"
            cmd = ['gobuster', 'dir', '-u', url, '-o', outfile, '-k', '-q']
            
            if tool_args: cmd.extend(tool_args.split())
            else: cmd.extend(['-w', '/usr/share/wordlists/dirb/common.txt'])

            try:
                subprocess.run(cmd, timeout=default_timeout or 600, capture_output=True)
                with open(outfile) as f:
                    for line in f:
                        l = line.strip()
                        if l: 
                            all_find.append(l)
                            target.add_json_result({"tool": "Gobuster", "url": url, "path": l})
            except Exception as e: all_find.append(f"[ERR] {url}: {e}")
        target.add_result(self.name, all_find)