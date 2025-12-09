#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import whois
from ..base_module import BaseModule

class WhoisModule(BaseModule):
    
    name = "Whois"

    def pre_run_check(self, target, profile):
        if target.target_str.replace('.', '').isdigit():
            return False
        return True

    # (ĐÃ SỬA) Thêm tool_args và default_timeout
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        print(f"[INFO] Bắt đầu quét Whois (dùng thư viện) trên: {target.target_str}...")
        
        try:
            whois_data = whois.whois(target.target_str)
            findings = self.parse_whois_data(whois_data)
            
            output_file = f"{target.project_dir}/whois_scan_{timestamp}.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(str(whois_data))
            
            target.add_result(self.name, findings)
            
        except Exception as e:
            msg = f"[LỖI] Whois (thư viện) chạy thất bại. Lỗi: {e}"
            print(msg)
            target.add_result(self.name, [msg])

    def parse_whois_data(self, data):
        findings = []
        if not data:
            return ["Không tìm thấy dữ liệu Whois."]
        def format_value(value):
            if isinstance(value, list):
                return ", ".join(v.strip() for v in value)
            return str(value).strip()
        key_fields = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 
                      'name_servers', 'status', 'emails', 'org', 'address', 'city', 'state', 'zipcode', 'country']
        for key in key_fields:
            value = data.get(key)
            if value:
                findings.append(f"  [+] {key.replace('_', ' ').title()}: {format_value(value)}")
        return findings