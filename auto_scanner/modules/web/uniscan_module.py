#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
from ..base_module import BaseModule

class UniscanModule(BaseModule):

    name = "Uniscan"

    def pre_run_check(self, target, profile):
        if profile != 'detailed': return False
        if not target.web_urls: return False
        return True

    # (ĐÃ SỬA)
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_findings = []
        print(f"[INFO] Bắt đầu quét Uniscan (chi tiết) trên {len(target.web_urls)} URL(s)...")
        timeout = default_timeout or 1800
        
        for url in target.web_urls:
            print(f"[INFO] Đang quét Uniscan trên: {url}...")
            safe_url_name = url.replace("://", "_").replace(":", "_").replace("/", "")
            output_file = f"{target.project_dir}/uniscan_scan_{safe_url_name}_{timestamp}.txt"
            
            command = ['uniscan']
            if tool_args:
                command.extend(tool_args.split())
                command.extend(['-u', url, '-o', output_file])
            else:
                command.extend(['-u', url, '-qwe', '-o', output_file])
            
            try:
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout) 
                print(f"[INFO] Uniscan scan hoàn tất cho {url}.")
                findings = self.parse_uniscan_txt(output_file)
                all_findings.extend(findings)
            except Exception as e:
                all_findings.append(f"[LỖI] Uniscan chạy thất bại cho {url}. Lỗi: {e}")
        
        target.add_result(self.name, all_findings)

    def parse_uniscan_txt(self, txt_file):
        findings = []
        try:
            with open(txt_file, 'r', encoding='utf-8') as f:
                capture = False
                for line in f:
                    line = line.strip()
                    if line.startswith("Directory check:") or line.startswith("File check:") or line.startswith("Interesting entries"):
                        capture = True
                        findings.append(f"--- {line} ---")
                        continue
                    if line.startswith("==="):
                        capture = False
                        continue
                    if capture and line:
                        findings.append(f"  [+] {line}")
            return findings
        except Exception as e:
            return [f"[LỖI] Xảy ra lỗi khi phân tích Uniscan TXT: {e}"]