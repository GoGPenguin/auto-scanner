#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import shutil
from ..base_module import BaseModule

class SkipfishModule(BaseModule):

    name = "Skipfish"

    def pre_run_check(self, target, profile):
        if not target.web_urls:
            return False
        if profile != 'detailed':
            print(f"[SKIP] Skipfish quá chậm, chỉ chạy ở profile 'detailed'.")
            return False
        return True

    # (ĐÃ SỬA)
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        all_findings = []
        print(f"[INFO] Bắt đầu quét Skipfish (chi tiết) trên {len(target.web_urls)} URL(s)...")
        timeout = default_timeout or 3600
        
        for url in target.web_urls:
            print(f"[INFO] Đang quét Skipfish trên: {url}...")
            safe_url_name = url.replace("://", "_").replace(":", "_").replace("/", "")
            output_dir = f"{target.project_dir}/skipfish_scan_{safe_url_name}_{timestamp}"
            
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            
            command = ['skipfish']
            if tool_args:
                command.extend(tool_args.split())
            
            command.extend(['-o', output_dir, url])
            
            try:
                subprocess.run(command, capture_output=True, text=True, timeout=timeout)
                report_link = f"file://{os.path.abspath(output_dir)}/index.html"
                findings = [
                    f"Skipfish đã chạy xong cho: {url}",
                    f"  [+] Báo cáo HTML chi tiết (mở bằng trình duyệt):",
                    f"  [+] {report_link}"
                ]
                all_findings.extend(findings)
                
            except Exception as e:
                all_findings.append(f"[LỖI] Skipfish chạy thất bại cho {url}. Lỗi: {e}")
        
        target.add_result(self.name, all_findings)