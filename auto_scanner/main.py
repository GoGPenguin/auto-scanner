#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AUTO-SCANNER FRAMEWORK v1.5 (Flexible & Timeout Control)
Entry point (điểm vào) cho giao diện dòng lệnh (CLI).
"""

import argparse
from .core import ScannerEngine

def main():
    print("===========================================")
    print("   AUTO-SCANNER FRAMEWORK (BẢN V1.5)  ")
    print("===========================================")
    
    parser = argparse.ArgumentParser(description="Framework quét tự động cho đề tài sinh viên (v1.5 Flexible).")
    
    # --- Nhóm Target ---
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', 
                              help="Mục tiêu cần quét (IP hoặc Domain)")
    target_group.add_argument('-iL', '--target-list', 
                              help="Tên file chứa danh sách mục tiêu (mỗi dòng 1 target)")
    
    # --- Nhóm Cấu hình Quét ---
    scan_config_group = parser.add_argument_group('Cấu hình Quét')
    scan_config_group.add_argument('-p', '--profile', choices=['fast', 'detailed'], default='fast', 
                                 help="Chọn profile quét: 'fast' (nhanh) hoặc 'detailed' (chậm, sâu). Mặc định: fast")
    scan_config_group.add_argument('-w', '--workers', type=int, default=10,
                                 help="Số lượng luồng (worker) chạy song song. Mặc định: 10")
    
    # (MỚI v1.5) Thêm cờ --timeout
    scan_config_group.add_argument('-to', '--timeout', type=int, default=None,
                                 help="Thời gian chờ (timeout) TỐI ĐA cho mỗi công cụ (tính bằng giây). "
                                      "Nếu không đặt, sẽ dùng timeout mặc định của profile.")

    # --- Nhóm Lựa chọn Module ---
    module_select_group = parser.add_argument_group('Lựa chọn Module')
    step_group = module_select_group.add_mutually_exclusive_group()
    step_group.add_argument('-s', '--steps', 
                            help="Các giai đoạn (NHÓM) cần chạy (phân tách bằng dấu phẩy). "
                                 "Mặc định: recon,network,web,exploit_prep")
    step_group.add_argument('--tools', 
                            help="Chạy các (TOOL) cụ thể (phân tách bằng dấu phẩy). "
                                 "Ví dụ: 'Nmap,Nikto,Gobuster'")
    
    # (MỚI v1.5) Thêm cờ --tool-args
    module_select_group.add_argument('-ta', '--tool-args', nargs='+', 
                                     help="Truyền tham số tùy chỉnh cho tool. "
                                          "Định dạng: \"ToolName: <args>\" "
                                          "Ví dụ: -ta \"Nmap: -A -T5\" \"Gobuster: -w /path/list.txt -x php\"")

    # --- Nhóm Báo cáo ---
    report_group = parser.add_argument_group('Cấu hình Báo cáo')
    report_group.add_argument('-ai', '--ai-summary', 
                              action='store_true', 
                              help="Bật tính năng tóm tắt báo cáo bằng Gemini AI. (Yêu cầu API Key)")
    
    args = parser.parse_args()
    
    # ----- BẮT ĐẦU BỘ NÃO -----
    try:
        engine = ScannerEngine(args)
        engine.load_modules()
        engine.load_targets()
        engine.start_scan()
        engine.generate_final_report()
        
    except KeyboardInterrupt:
        print("\n[INFO] Người dùng yêu cầu dừng... Đang thoát.")
    except Exception as e:
        print(f"\n[LỖI NGHIÊM TRỌNG] Xảy ra lỗi ngoài dự kiến: {e}")

if __name__ == "__main__":
    main()