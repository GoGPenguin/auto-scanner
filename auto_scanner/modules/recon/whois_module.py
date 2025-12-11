#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import whois
from ..base_module import BaseModule

class WhoisModule(BaseModule):
    name = "Whois"
    tag = "recon"
    
    def pre_run_check(self, target, profile):
        return not target.target_str.replace('.', '').isdigit()

    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        try:
            w = whois.whois(target.target_str)
            output = str(w)
            with open(f"{target.project_dir}/whois_{timestamp}.txt", 'w') as f: f.write(output)
            
            # Parse Text
            findings = []
            for k in ['domain_name', 'registrar', 'emails']:
                v = w.get(k)
                if v: findings.append(f"  [+] {k}: {v}")
            target.add_result(self.name, findings)
            
            # Parse JSON for ELK
            target.add_json_result({"tool": "Whois", "raw": output})
            
        except Exception as e:
            target.add_result(self.name, [f"[ERR] {e}"])