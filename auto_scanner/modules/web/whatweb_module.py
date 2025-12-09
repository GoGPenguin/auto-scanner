#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import json
from ..base_module import BaseModule

class WhatWebModule(BaseModule):
    
    name = "WhatWeb"
    
    def pre_run_check(self, target, profile):
        """Chỉ chạy nếu Nmap đã tìm thấy cổng web."""
        if not target.web_urls:
            return False
        return True

    def run(self, target, profile, timestamp):
        all_findings = []
        print(f"[INFO] Bắt đầu quét WhatWeb trên {len(target.web_urls)} URL(s)...")
        
        for url in target.web_urls:
            safe_url_name = url.replace("://", "_").replace(":", "_").replace("/", "")
            output_file = f"{target.project_dir}/whatweb_scan_{safe_url_name}_{timestamp}.json"
            command = ['whatweb', '-a', '3', f'--log-json={output_file}', url]
            
            try:
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    print(f"[INFO] WhatWeb scan hoàn tất cho {url}.")
                    findings = self.parse_whatweb_json(output_file)
                    all_findings.extend(findings)
                else:
                    all_findings.append(f"[WARN] WhatWeb chạy nhưng không tạo file output cho {url}.")
            except Exception as e:
                all_findings.append(f"[LỖI] WhatWeb chạy thất bại cho {url}. Lỗi: {e}")
        
        target.add_result(self.name, all_findings)

    def parse_whatweb_json(self, json_file):
        findings = []
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data_list = json.load(f) 
                if not isinstance(data_list, list): data_list = [data_list]
                for data in data_list:
                    findings.append(f"Kết quả cho: {data.get('target')}")
                    plugins = data.get('plugins', {})
                    if not plugins:
                        findings.append("  [?] Không nhận diện được công nghệ cụ thể.")
                        continue
                    for plugin_name, info in plugins.items():
                        details = []
                        if 'version' in info: details.append(f"Version: {info['version']}")
                        if 'string' in info: details.append(f"Info: {info['string']}")
                        if 'module' in info: details.append(f"Module: {info['module']}")
                        if details:
                            findings.append(f"  [+] {plugin_name}: {', '.join(str(d) for d in details)}")
                        else:
                            findings.append(f"  [+] {plugin_name}")
            return findings
        except Exception as e:
            return [f"[LỖI] Xảy ra lỗi khi phân tích WhatWeb JSON: {e}"]