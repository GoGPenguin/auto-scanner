#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from datetime import datetime

# --- AI & Elastic ---
try:
    import google.generativeai as genai
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

try:
    from elasticsearch import Elasticsearch
    ELASTIC_AVAILABLE = True
except ImportError:
    ELASTIC_AVAILABLE = False

def export_to_elasticsearch(targets):
    if not ELASTIC_AVAILABLE:
        print("[SKIP] Bỏ qua Export ELK (Chưa cài 'elasticsearch').")
        return

    ES_HOST = os.getenv("ES_HOST", "http://localhost:9200") 
    INDEX_NAME = "auto-scanner-logs"
    print(f"[INFO] Đang kết nối đến Elasticsearch tại {ES_HOST}...")
    
    try:
        es = Elasticsearch(hosts=[ES_HOST], verify_certs=False)
        if not es.ping():
            print(f"[LỖI] Không thể ping thấy Elasticsearch tại {ES_HOST}.")
            return

        total_docs = 0
        for target in targets:
            if not target.json_results: continue
            for record in target.json_results:
                if 'timestamp' not in record:
                    record['timestamp'] = datetime.now().isoformat()
                try:
                    es.index(index=INDEX_NAME, document=record)
                    total_docs += 1
                except Exception: pass
        print(f"[OK] Đã đẩy thành công {total_docs} bản ghi lên Elasticsearch.")
    except Exception as e:
        print(f"[LỖI] Quá trình export ELK thất bại: {e}")

def write_findings_with_analysis(f, findings_list, tool_name=""):
    for line in findings_list:
        f.write(f"{line}\n")
        line_lower = line.lower()
        if tool_name == "Gobuster":
            if "/.svn/" in line_lower:
                f.write("      => PHÂN TÍCH: Thư mục .svn bị lộ.\n")
            elif "/.git/" in line_lower:
                f.write("      => PHÂN TÍCH: Thư mục .git bị lộ.\n")
        if tool_name == "Nikto" and "x-frame-options" in line_lower:
            f.write("      => PHÂN TÍCH: Thiếu Header X-Frame-Options.\n")
        if tool_name == "Nmap" and "vulnerable" in line_lower:
            f.write("      => PHÂN TÍCH: NSE xác nhận lỗ hổng.\n")

def generate_combined_report(targets, profile, timestamp, scan_dir):
    report_file_path = f"{scan_dir}/REPORT_TONG_HOP_{timestamp}.txt"
    print(f"[INFO] Đang tạo báo cáo tại: {report_file_path}")
    try:
        with open(report_file_path, 'w', encoding='utf-8') as f:
            for target in targets:
                f.write("\n" + "="*60 + "\n")
                f.write(f" BÁO CÁO MỤC TIÊU: {target.target_str}\n")
                f.write("="*60 + "\n")
                if not target.results:
                    f.write("\nKhông có kết quả.\n")
                    continue
                
                PHASE_ORDER = {'recon': 1, 'network': 2, 'web': 3, 'exploit_prep': 4}
                sorted_module_names = sorted(
                    target.results.keys(), 
                    key=lambda m: PHASE_ORDER.get(target.get_module_tag_by_name(m), 99)
                )

                for module_name in sorted_module_names:
                    findings = target.results[module_name]
                    f.write(f"\n--- {module_name.upper()} ---\n")
                    write_findings_with_analysis(f, findings, module_name)
        
        with open(report_file_path, 'r', encoding='utf-8') as f:
            return report_file_path, f.read()
    except IOError as e:
        print(f"[LỖI] Không thể ghi file báo cáo: {e}")
        return None, None

def get_ai_summary(report_content):
    if not AI_AVAILABLE: return "Thiếu thư viện google-generativeai."
    API_KEY = os.getenv("GEMINI_API_KEY")
    if not API_KEY: return "Thiếu API Key."
    
    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel('gemini-flash-latest')
    try:
        response = model.generate_content(f"Tóm tắt kỹ thuật bảo mật:\n{report_content}")
        return response.text
    except Exception as e:
        return f"Lỗi AI: {e}"

def prepend_ai_summary_to_report(report_file_path, ai_summary):
    try:
        with open(report_file_path, 'r', encoding='utf-8') as f: original = f.read()
        with open(report_file_path, 'w', encoding='utf-8') as f:
            f.write("=== AI SUMMARY ===\n\n" + ai_summary + "\n\n=== DETAILS ===\n" + original)
    except Exception: pass