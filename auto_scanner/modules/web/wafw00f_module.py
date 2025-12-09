#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from ..base_module import BaseModule

class Wafw00fModule(BaseModule):

    name = "WAFW00F"

    def pre_run_check(self, target, profile):
        return bool(target.web_urls)

    # (ĐÃ SỬA)
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        print(f"[INFO] Bắt đầu quét WAFW00F trên {len(target.web_urls)} URL(s)...")
        all_findings = []
        timeout = default_timeout or 120
        
        for url in target.web_urls:
            safe_url_name = url.replace("://", "_").replace(":", "_").replace("/", "")
            output_file = f"{target.project_dir}/wafw00f_scan_{safe_url_name}_{timestamp}.txt"
            
            command = ['wafw00f']
            if tool_args:
                command.extend(tool_args.split())
            command.extend(['-o', output_file, '-f', 'text', url])
            
            try:
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
                print(f"[INFO] WAFW00F scan hoàn tất cho {url}.")
                findings = self.parse_wafw00f_txt(output_file)
                all_findings.extend(findings)
            except Exception as e:
                msg = f"[LỖI] WAFW00F chạy thất bại cho {url}. Lỗi: {e}"
                print(msg)
                all_findings.append(msg)
                
        target.add_result(self.name, all_findings)

    def parse_wafw00f_txt(self, txt_file):
        findings = []
        try:
            with open(txt_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if "is behind a" in line:
                        waf_name = line.split("is behind a")[-1].strip().replace("WAF", "").strip()
                        findings.append(f"  [!!!] PHÁT HIỆN TƯỜNG LỬA (WAF): {waf_name}")
                        findings.append(f"      => CẢNH BÁO: Kết quả quét (Nikto, Gobuster) có thể không đầy đủ/chính xác do bị WAF chặn.")
                        return findings
            findings.append("  [+] Không phát hiện thấy WAF (Tường lửa ứng dụng web) nào.")
            return findings
        except Exception as e:
            return [f"[LỖI] Xảy ra lỗi khi phân tích WAFW00F TXT: {e}"]