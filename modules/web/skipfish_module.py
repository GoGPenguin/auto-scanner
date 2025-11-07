#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import shutil
from ..base_module import BaseModule

class SkipfishModule(BaseModule):

    name = "Skipfish"

    def pre_run_check(self, target, profile):
        """Chỉ chạy nếu Nmap đã tìm thấy cổng web."""
        if not target.web_urls:
            return False
        
        # Skipfish tạo ra RẤT NHIỀU file, không nên chạy ở 'fast'
        if profile != 'detailed':
            print(f"[SKIP] Skipfish quá chậm, chỉ chạy ở profile 'detailed'.")
            return False
        
        return True

    def run(self, target, profile, timestamp):
        all_findings = []
        print(f"[INFO] Bắt đầu quét Skipfish (chi tiết) trên {len(target.web_urls)} URL(s)...")
        
        for url in target.web_urls:
            print(f"[INFO] Đang quét Skipfish trên: {url}...")
            # Skipfish yêu cầu một thư mục output rỗng
            safe_url_name = url.replace("://", "_").replace(":", "_").replace("/", "")
            output_dir = f"{target.project_dir}/skipfish_scan_{safe_url_name}_{timestamp}"
            
            # Xóa thư mục cũ nếu tồn tại (để skipfish chạy được)
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            
            # Lệnh skipfish
            command = ['skipfish', '-o', output_dir, url]
            
            try:
                # Skipfish chạy rất lâu và tương tác
                subprocess.run(command, capture_output=True, text=True, timeout=3600) # 1 giờ
                
                # Chúng ta không parse kết quả HTML của skipfish (quá phức tạp)
                # Chúng ta chỉ thông báo cho người dùng nơi xem
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