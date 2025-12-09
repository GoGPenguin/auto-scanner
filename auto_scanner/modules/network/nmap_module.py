#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
try:
    import xml.etree.ElementTree as ET
except ImportError:
    print("[LỖI] Không thể nhập thư viện 'xml.etree.ElementTree'.")
    exit(1)

from ..base_module import BaseModule

class NmapModule(BaseModule):
    
    name = "Nmap"
    
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        """
        (NÂNG CẤP v1.5) Thực thi Nmap, ưu tiên tham số tùy chỉnh.
        """
        print(f"[INFO] Bắt đầu quét Nmap (Profile: {profile}) trên: {target.target_str}...")
        
        output_file = f"{target.project_dir}/nmap_scan_{timestamp}.xml"
        
        # 1. Xây dựng lệnh (Command)
        command = ['nmap', '-Pn', '-oX', output_file, target.target_str]
        
        if os.geteuid() == 0:
            command.insert(2, '-O') # Thêm -O nếu là root
            
        if tool_args:
            # Kịch bản 1: Người dùng cung cấp tham số tùy chỉnh
            print(f"[INFO] Sử dụng tham số Nmap tùy chỉnh: {tool_args}")
            command.extend(tool_args.split())
        else:
            # Kịch bản 2: Dùng profile
            command.append('-sV') # Quét phiên bản
            if profile == 'detailed':
                print("[INFO] Nmap dùng profile 'detailed' (-p- --script=vuln)")
                command.extend(['-p-', '--script=vuln'])
            else:
                print("[INFO] Nmap dùng profile 'fast' (-F)")
                command.append('-F')
        
        # 2. Xử lý Timeout
        # Ưu tiên timeout của người dùng
        if default_timeout:
            timeout = default_timeout
        # Nếu không, dùng timeout của profile
        elif profile == 'detailed':
            timeout = 7200 # 2 giờ
        else:
            timeout = 900 # 15 phút
        
        print(f"[INFO] Nmap timeout được đặt là: {timeout} giây")

        # 3. Chạy lệnh
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
            print(f"[INFO] Nmap scan hoàn tất. Đã lưu vào: {output_file}")
            
            findings, web_urls, ssl_ports, ip = self.parse_nmap_xml(output_file)
            
            if ip: target.ip = ip
            if web_urls: target.web_urls = web_urls
            if ssl_ports: target.ssl_ports = ssl_ports
            
            target.add_result(self.name, findings)
            
        except subprocess.TimeoutExpired:
            msg = f"[LỖI] Nmap scan quá thời gian chờ ({timeout} giây)."
            print(msg)
            target.add_result(self.name, [msg])
        except Exception as e:
            msg = f"[LỖI] Nmap chạy thất bại. Lỗi: {e}"
            print(msg)
            target.add_result(self.name, [msg])

    def parse_nmap_xml(self, xml_file):
        # (Hàm này không thay đổi)
        print(f"[INFO] Đang phân tích file kết quả Nmap: {xml_file}...")
        findings, web_target_urls, ssl_ports, ip_address = [], [], [], None
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                status_elem = host.find('status')
                if status_elem is None or status_elem.get('state') != 'up': continue 
                address_elem = host.find('address')
                if address_elem is not None: ip_address = address_elem.get('addr')
                else: continue 
                findings.append(f"Mục tiêu IP: {ip_address}")
                os_match = host.find('.//osmatch')
                if os_match is not None: findings.append(f"Hệ điều hành: {os_match.get('name')}")
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_id = port.get('portid')
                        state_elem = port.find('state')
                        if state_elem is None or state_elem.get('state') != 'open': continue 
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_name = service_elem.get('name', 'unknown')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            tunnel = service_elem.get('tunnel', '')
                        else: service_name, product, version, tunnel = 'unknown', '', '', ''
                        port_info = f"  [+] Cổng {port_id}/tcp (Mở) - Dịch vụ: {service_name} {product} {version}".strip()
                        findings.append(port_info)
                        for script in port.findall('script'):
                            script_id, script_output = script.get('id', 'unknown'), script.get('output', '').strip()
                            if ('vuln' in script_id or script_id == 'http-title') and script_output:
                                findings.append(f"    [!] NSE Script ({script_id}):")
                                is_vulnerable = False
                                for elem in script.findall(".//*"): 
                                    if elem.get('key') == 'state' and 'VULNERABLE' in elem.text:
                                        is_vulnerable = True
                                        findings.append(f"      [!!!] TRẠNG THÁI: {elem.text.strip()}")
                                        break
                                if not is_vulnerable and script_output:
                                    for line in script_output.splitlines():
                                        findings.append(f"      [INFO] {line.strip()}")
                        if 'http' in service_name:
                            if tunnel == 'ssl' or service_name == 'https':
                                web_target_urls.append(f"https://{ip_address}:{port_id}")
                                if port_id not in ssl_ports: ssl_ports.append(port_id)
                            else:
                                web_target_urls.append(f"http://{ip_address}:{port_id}")
                        elif service_name == 'ssl' or tunnel == 'ssl':
                            if port_id not in ssl_ports: ssl_ports.append(port_id)
            print("[OK] Phân tích Nmap XML thành công.")
            return findings, web_target_urls, ssl_ports, ip_address
        except ET.ParseError as e:
            print(f"[LỖI] File XML không hợp lệ. Lỗi: {e}")
            return [], [], [], None
        except Exception as e:
            print(f"[LỖI] Xảy ra lỗi ngoài dự kiến khi phân tích Nmap XML: {e}")
            return [], [], [], None