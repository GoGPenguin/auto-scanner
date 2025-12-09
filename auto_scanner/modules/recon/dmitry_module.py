#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
from ..base_module import BaseModule

class DmitryModule(BaseModule):

    name = "Dmitry"

    def pre_run_check(self, target, profile):
        """
        (NÂNG CẤP) Chạy ở cả 2 profile, miễn không phải là IP.
        """
        if target.target_str.replace('.', '').isdigit():
            return False
        return True

    def run(self, target, profile, timestamp):
        print(f"[INFO] Bắt đầu quét Dmitry (Profile: {profile}) trên: {target.target_str}...")
        output_file_base = f"{target.project_dir}/dmitry_scan_{timestamp}"
        output_file_txt = f"{output_file_base}.txt"
        
        # (NÂNG CẤP) Chọn lệnh dựa trên profile
        if profile == 'detailed':
            # Chạy đầy đủ (Quét Cổng + Subdomain)
            command = ['dmitry', '-ops', '-o', output_file_base, target.target_str]
        else:
            # Chạy nhanh (chỉ Whois/Netcraft)
            command = ['dmitry', '-o', output_file_base, target.target_str]
        
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
            print(f"[INFO] Dmitry scan hoàn tất. Đã lưu vào: {output_file_txt}")
            
            # (NÂNG CẤP) Gọi hàm parse đã được nâng cấp
            findings = self.parse_dmitry_txt(output_file_txt)
            target.add_result(self.name, findings)
            
        except Exception as e:
            msg = f"[LỖI] Dmitry chạy thất bại. Lỗi: {e}"
            print(msg)
            target.add_result(self.name, [msg])

    def parse_dmitry_txt(self, txt_file):
        """
        (NÂNG CẤP) Phân tích file TXT của Dmitry.
        Giờ đây đọc cả 3 mục: Portscan, Subdomain, và Email.
        """
        findings = []
        try:
            with open(txt_file, 'r', encoding='utf-8') as f:
                
                # Biến cờ (flag) để biết đang đọc phần nào
                in_portscan_section = False
                in_subdomain_section = False
                in_email_section = False
                
                for line in f:
                    line = line.strip()
                    
                    # --- Kiểm tra bắt đầu các mục ---
                    if "Portscan results for" in line:
                        in_portscan_section = True
                        findings.append("\n  [+] Kết quả Quét Cổng (từ Dmitry):")
                        continue
                    elif "Subdomains found" in line:
                        in_portscan_section = False # Dừng mục trước
                        in_subdomain_section = True
                        findings.append("\n  [+] Các Subdomain tìm thấy (từ Dmitry):")
                        continue
                    elif "Email addresses found" in line:
                        in_portscan_section = False
                        in_subdomain_section = False # Dừng mục trước
                        in_email_section = True
                        findings.append("\n  [+] Các Email tìm thấy (từ Dmitry):")
                        continue
                    
                    # --- Đọc dữ liệu ---
                    if in_portscan_section:
                        if line.startswith("Port") or line.startswith("----"):
                            continue # Bỏ qua header của bảng
                        if line:
                            findings.append(f"    - {line}")
                    
                    elif in_subdomain_section:
                        if line:
                            findings.append(f"    - {line}")
                        else:
                            in_subdomain_section = False # Dừng khi gặp dòng trống
                            
                    elif in_email_section:
                        if line:
                            findings.append(f"    - {line}")
                        else:
                            in_email_section = False # Dừng khi gặp dòng trống
            
            return findings
            
        except Exception as e:
            return [f"[LỖI] Xảy ra lỗi khi phân tích Dmitry TXT: {e}"]