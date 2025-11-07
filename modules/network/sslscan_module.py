#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
try:
    import xml.etree.ElementTree as ET
except ImportError:
    print("[LỖI] Không thể nhập thư viện 'xml.etree.ElementTree'.")
    exit(1)
    
from ..base_module import BaseModule

class SslScanModule(BaseModule):

    name = "SSLScan"

    def pre_run_check(self, target, profile):
        """Chỉ chạy nếu Nmap đã tìm thấy cổng SSL."""
        if not target.ssl_ports:
            return False
        if not target.ip: # Cần IP để quét
            print(f"[SKIP] Bỏ qua SSLScan cho {target.target_str} (chưa xác định được IP).")
            return False
        return True

    def run(self, target, profile, timestamp):
        print(f"[INFO] Bắt đầu quét SSLScan trên {len(target.ssl_ports)} cổng SSL...")
        all_findings = []
        
        for port in target.ssl_ports:
            print(f"[INFO] Đang quét SSLScan trên: {target.ip}:{port}...")
            output_file = f"{target.project_dir}/sslscan_{port}_{timestamp}.xml"
            command = ['sslscan', f"{target.ip}:{port}", f"--xml={output_file}", "--no-colour"]
            
            try:
                subprocess.run(command, check=True, capture_output=True, text=True, timeout=300)
                print(f"[INFO] SSLScan hoàn tất. Đã lưu vào: {output_file}")
                findings = self.parse_sslscan_xml(output_file)
                all_findings.extend(findings)
                all_findings.append("-" * 20)
            except Exception as e:
                msg = f"[LỖI] SSLScan chạy thất bại cho cổng {port}. Lỗi: {e}"
                print(msg)
                all_findings.append(msg)
                
        target.add_result(self.name, all_findings)

    def parse_sslscan_xml(self, xml_file):
        findings = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            port = root.find('.//ssltest').get('port')
            findings.append(f"Kết quả quét cho cổng: {port}")
            for protocol in root.findall('.//protocol'):
                if protocol.get('enabled') == '1':
                    findings.append(f"  [!] {protocol.get('type').upper()} {protocol.get('version')}: Bật (Yếu)")
            for vuln in root.findall('.//heartbleed'):
                if vuln.get('vulnerable') == '1':
                    findings.append("  [!!!] LỖ HỔNG: Heartbleed (CVE-2014-0160)!")
            return findings
        except Exception as e:
            return [f"[LỖI] Xảy ra lỗi khi phân tích SSLScan XML: {e}"]