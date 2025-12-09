#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from ..base_module import BaseModule

class DmitryModule(BaseModule):

    name = "Dmitry"

    def pre_run_check(self, target, profile):
        if target.target_str.replace('.', '').isdigit():
            return False
        return True

    # (ĐÃ SỬA)
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        print(f"[INFO] Bắt đầu quét Dmitry (Profile: {profile}) trên: {target.target_str}...")
        output_file_base = f"{target.project_dir}/dmitry_scan_{timestamp}"
        output_file_txt = f"{output_file_base}.txt"
        
        command = ['dmitry']
        
        # Ưu tiên tool_args
        if tool_args:
             command.extend(tool_args.split())
             command.extend(['-o', output_file_base, target.target_str])
        elif profile == 'detailed':
            command.extend(['-ops', '-o', output_file_base, target.target_str])
        else:
            command.extend(['-o', output_file_base, target.target_str])
        
        timeout = default_timeout or 300

        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            print(f"[INFO] Dmitry scan hoàn tất. Đã lưu vào: {output_file_txt}")
            findings = self.parse_dmitry_txt(output_file_txt)
            target.add_result(self.name, findings)
        except Exception as e:
            msg = f"[LỖI] Dmitry chạy thất bại. Lỗi: {e}"
            print(msg)
            target.add_result(self.name, [msg])

    def parse_dmitry_txt(self, txt_file):
        findings = []
        try:
            with open(txt_file, 'r', encoding='utf-8') as f:
                in_portscan_section = False
                in_subdomain_section = False
                in_email_section = False
                for line in f:
                    line = line.strip()
                    if "Portscan results for" in line:
                        in_portscan_section = True
                        findings.append("\n  [+] Kết quả Quét Cổng (từ Dmitry):")
                        continue
                    elif "Subdomains found" in line:
                        in_portscan_section = False
                        in_subdomain_section = True
                        findings.append("\n  [+] Các Subdomain tìm thấy (từ Dmitry):")
                        continue
                    elif "Email addresses found" in line:
                        in_portscan_section = False
                        in_subdomain_section = False
                        in_email_section = True
                        findings.append("\n  [+] Các Email tìm thấy (từ Dmitry):")
                        continue
                    
                    if in_portscan_section:
                        if line.startswith("Port") or line.startswith("----"): continue
                        if line: findings.append(f"    - {line}")
                    elif in_subdomain_section:
                        if line: findings.append(f"    - {line}")
                        else: in_subdomain_section = False
                    elif in_email_section:
                        if line: findings.append(f"    - {line}")
                        else: in_email_section = False
            return findings
        except Exception as e:
            return [f"[LỖI] Xảy ra lỗi khi phân tích Dmitry TXT: {e}"]