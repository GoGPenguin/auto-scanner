#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import json
from ..base_module import BaseModule

class NiktoModule(BaseModule):

    name = "Nikto"

    def pre_run_check(self, target, profile):
        """Chỉ chạy nếu Nmap đã tìm thấy cổng web."""
        return bool(target.web_urls)

    def run(self, target, profile, timestamp):
        all_findings = []
        print(f"[INFO] Bắt đầu quét Nikto trên {len(target.web_urls)} URL(s)...")
        
        for url in target.web_urls:
            print(f"[INFO] Đang quét Nikto trên: {url}...")
            safe_url_name = url.replace("://", "_").replace(":", "_").replace("/", "")
            output_file = f"{target.project_dir}/nikto_scan_{safe_url_name}_{timestamp}.json"
            command = ['nikto', '-h', url, '-o', output_file, '-Format', 'json']
            
            try:
                subprocess.run(command, capture_output=True, text=True, timeout=1800) # 30 phút
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    print(f"[INFO] Nikto scan hoàn tất cho {url}.")
                    findings = self.parse_nikto_json(output_file)
                    all_findings.extend(findings)
                else:
                    all_findings.append(f"[WARN] Nikto chạy nhưng không tạo file output cho {url}.")
            except Exception as e:
                all_findings.append(f"[LỖI] Nikto chạy thất bại cho {url}. Lỗi: {e}")
        
        target.add_result(self.name, all_findings)

    def parse_nikto_json(self, json_file):
        findings = []
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                host_info = f"Kết quả cho Host: {data.get('host')} (IP: {data.get('ip')})"
                findings.append(host_info)
                findings.append(f"Banner Server: {data.get('banner')}")
                for item in data.get('vulnerabilities', []):
                    line = f"  [+] {item.get('method')} {item.get('url')} - {item.get('msg')}"
                    findings.append(line.strip())
            return findings
        except Exception as e:
            return [f"[LỖI] Xảy ra lỗi khi phân tích Nikto JSON: {e}"]