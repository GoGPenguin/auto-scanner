#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# (MỚI) Import thư viện whois
import whois
from ..base_module import BaseModule

class WhoisModule(BaseModule):
    
    name = "Whois"

    def pre_run_check(self, target, profile):
        """Chỉ chạy nếu mục tiêu không phải là IP."""
        if target.target_str.replace('.', '').isdigit():
            return False
        return True

    def run(self, target, profile, timestamp):
        """
        (NÂNG CẤP) Sử dụng thư viện 'python-whois' thay vì subprocess
        để tự động parse kết quả.
        """
        print(f"[INFO] Bắt đầu quét Whois (dùng thư viện) trên: {target.target_str}...")
        
        try:
            # 1. Chạy whois
            # Thư viện này tự động xử lý các loại registrar khác nhau
            whois_data = whois.whois(target.target_str)
            
            # 2. Parse kết quả (dễ dàng)
            findings = self.parse_whois_data(whois_data)
            
            # 3. Ghi file (tùy chọn, để debug)
            output_file = f"{target.project_dir}/whois_scan_{timestamp}.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(str(whois_data))
            
            target.add_result(self.name, findings)
            
        except Exception as e:
            msg = f"[LỖI] Whois (thư viện) chạy thất bại. Lỗi: {e}"
            print(msg)
            target.add_result(self.name, [msg])

    def parse_whois_data(self, data):
        """
        (NÂNG CẤP) Phân tích đối tượng dictionary trả về từ thư viện.
        """
        findings = []
        if not data:
            return ["Không tìm thấy dữ liệu Whois."]
            
        # Chuyển đổi các giá trị (có thể là list) thành chuỗi
        def format_value(value):
            if isinstance(value, list):
                return ", ".join(v.strip() for v in value)
            return str(value).strip()

        # Lấy các trường quan trọng
        key_fields = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 
                      'name_servers', 'status', 'emails', 'org', 'address', 'city', 'state', 'zipcode', 'country']
        
        for key in key_fields:
            value = data.get(key)
            if value:
                findings.append(f"  [+] {key.replace('_', ' ').title()}: {format_value(value)}")
        
        return findings