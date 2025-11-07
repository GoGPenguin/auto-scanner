#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
from ..base_module import BaseModule

class GobusterModule(BaseModule):

    name = "Gobuster"

    def pre_run_check(self, target, profile):
        return bool(target.web_urls)

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        """
        (NÂNG CẤP v1.5) Thực thi Gobuster, ưu tiên tham số tùy chỉnh.
        """
        all_findings = []
        print(f"[INFO] Bắt đầu quét Gobuster (Profile: {profile}) trên {len(target.web_urls)} URL(s)...")
        
        # 1. Xử lý Timeout
        timeout = default_timeout or 600 # 10 phút mặc định

        for url in target.web_urls:
            print(f"[INFO] Đang quét Gobuster trên: {url}...")
            safe_url_name = url.replace("://", "_").replace(":", "_").replace("/", "")
            output_file = f"{target.project_dir}/gobuster_scan_{safe_url_name}_{timestamp}.txt"
            
            # 2. Xây dựng lệnh (Command)
            command = ['gobuster', 'dir', '-u', url, '-o', output_file, '-k', '-q']
            
            if tool_args:
                # Kịch bản 1: Người dùng cung cấp tham số tùy chỉnh
                print(f"[INFO] Sử dụng tham số Gobuster tùy chỉnh: {tool_args}")
                command.extend(tool_args.split())
            else:
                # Kịch bản 2: Dùng profile
                if profile == 'detailed':
                    wordlist = "/usr/share/wordlists/dirb/big.txt"
                else:
                    wordlist = "/usr/share/wordlists/dirb/common.txt"
                
                if not os.path.exists(wordlist):
                    wordlist = "/usr/share/wordlists/dirb/common.txt" # Quay về common
                
                if not os.path.exists(wordlist):
                    all_findings.append(f"[LỖI] Không tìm thấy wordlist: {wordlist}")
                    continue
                
                print(f"[INFO] Gobuster dùng wordlist: {wordlist}")
                command.extend(['-w', wordlist])
            
            # 3. Chạy lệnh
            try:
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
                print(f"[INFO] Gobuster scan hoàn tất cho {url}.")
                findings = self.parse_gobuster_txt(output_file)
                all_findings.extend(findings)
            except subprocess.TimeoutExpired:
                msg = f"[LỖI] Gobuster scan quá thời gian chờ ({timeout} giây) cho {url}."
                print(msg)
                all_findings.append(msg)
            except Exception as e:
                all_findings.append(f"[LỖI] Gobuster chạy thất bại cho {url}. Lỗi: {e}")
        
        target.add_result(self.name, all_findings)

    def parse_gobuster_txt(self, txt_file):
        # (Không thay đổi)
        findings = []
        try:
            with open(txt_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        findings.append(f"  [+] {line}")
            return findings
        except Exception as e:
            return [f"[LỖI] Xảy ra lỗi khi phân tích Gobuster TXT: {e}"]