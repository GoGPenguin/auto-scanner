#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
from .core import ScannerEngine

def main():
    print("===========================================")
    print("   AUTO-SCANNER FRAMEWORK (V1.6 ELK)  ")
    print("===========================================")
    
    parser = argparse.ArgumentParser()
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help="Mục tiêu (IP/Domain)")
    target_group.add_argument('-iL', '--target-list', help="File danh sách mục tiêu")
    
    parser.add_argument('-p', '--profile', choices=['fast', 'detailed'], default='fast')
    parser.add_argument('-w', '--workers', type=int, default=10)
    parser.add_argument('-to', '--timeout', type=int, default=None, help="Global timeout (giây)")
    
    module_group = parser.add_mutually_exclusive_group()
    module_group.add_argument('-s', '--steps', default='recon,network,web,exploit_prep,export')
    module_group.add_argument('--tools', help="Chạy tool cụ thể (vd: Nmap,Nikto)")
    
    parser.add_argument('-ta', '--tool-args', nargs='+', help="Tham số tùy chỉnh (vd: 'Nmap: -T4')")
    parser.add_argument('-ai', '--ai-summary', action='store_true', help="Tóm tắt AI")
    
    args = parser.parse_args()
    
    try:
        engine = ScannerEngine(args)
        engine.load_modules()
        engine.load_targets()
        engine.start_scan()
        engine.generate_final_report()
    except KeyboardInterrupt:
        print("\n[STOP] Đã dừng bởi người dùng.")
    except Exception as e:
        print(f"\n[LỖI] {e}")

if __name__ == "__main__":
    main()