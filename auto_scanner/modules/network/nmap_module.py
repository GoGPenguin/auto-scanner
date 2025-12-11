#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
import os
import xml.etree.ElementTree as ET
from ..base_module import BaseModule

class NmapModule(BaseModule):
    name = "Nmap"
    tag = "network"

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        outfile = f"{target.project_dir}/nmap_{timestamp}.xml"
        cmd = ['nmap', '-Pn', '-oX', outfile, target.target_str]
        
        if tool_args: cmd.extend(tool_args.split())
        else: 
            cmd.append('-F') if profile == 'fast' else cmd.extend(['-p-', '--script=vuln'])

        try:
            subprocess.run(cmd, timeout=default_timeout or (900 if profile == 'fast' else 7200), check=True, capture_output=True)
            
            # Parse
            findings, urls, ssls, ip = self.parse_nmap_xml(outfile, target)
            if ip: target.ip = ip
            if urls: target.web_urls = urls
            if ssls: target.ssl_ports = ssls
            target.add_result(self.name, findings)
            
        except Exception as e:
            target.add_result(self.name, [f"[ERR] {e}"])

    def parse_nmap_xml(self, xml, target):
        findings, urls, ssls, ip = [], [], [], None
        try:
            tree = ET.parse(xml)
            for host in tree.getroot().findall('host'):
                if host.find('status').get('state') == 'up':
                    ip = host.find('address').get('addr')
                    for port in host.find('ports').findall('port'):
                        if port.find('state').get('state') == 'open':
                            pid = port.get('portid')
                            svc = port.find('service')
                            sname = svc.get('name', 'unknown') if svc is not None else 'unknown'
                            ver = svc.get('version', '') if svc is not None else ''
                            
                            findings.append(f"Port {pid}: {sname} {ver}")
                            
                            # JSON for ELK
                            target.add_json_result({
                                "tool": "Nmap",
                                "ip": ip,
                                "port": int(pid),
                                "service": sname,
                                "version": ver
                            })

                            if 'http' in sname or pid in ['80','443','8080']:
                                proto = 'https' if 'ssl' in sname or pid=='443' else 'http'
                                urls.append(f"{proto}://{ip}:{pid}")
                                if proto == 'https': ssls.append(pid)
            return findings, urls, ssls, ip
        except: return [], [], [], None