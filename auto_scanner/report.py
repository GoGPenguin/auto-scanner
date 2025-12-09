#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from datetime import datetime

# --- Tích hợp AI (v0.6) ---
try:
    import google.generativeai as genai
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("[INFO] Không tìm thấy thư viện 'google.generativeai'. Tóm tắt AI sẽ bị tắt.")


# --- Hàm phân tích Rule-based (v0.5) ---
def write_findings_with_analysis(f, findings_list, tool_name=""):
    for line in findings_list:
        f.write(f"{line}\n")
        line_lower = line.lower()
        
        if tool_name == "Gobuster":
            if "/.svn/" in line_lower:
                f.write("      => PHÂN TÍCH (NGHIÊM TRỌNG): Thư mục .svn (Subversion) bị lộ.\n")
                f.write("         Kẻ tấn công có thể dùng nó để tải về TOÀN BỘ MÃ NGUỒN (source code).\n")
                f.write("      => KHẮC PHỤC: Cấu hình máy chủ web để CHẶN truy cập công khai vào '.svn'.\n")
            elif "/.git/" in line_lower:
                f.write("      => PHÂN TÍCH (NGHIÊM TRỌNG): Thư mục .git bị lộ.\n")
                f.write("      => KHẮC PHỤC: Cấu hình máy chủ web để CHẶN truy cập công khai vào '.git'.\n")
            elif ("/server-status" in line_lower or "/server-info" in line_lower) and "403" not in line_lower:
                f.write("      => PHÂN TÍCH (CAO): Trang 'server-status' của Apache bị lộ.\n")
                f.write("      => KHẮC PHỤC: Tắt 'mod_status' hoặc chỉ cho phép truy cập từ IP nội bộ.\n")
                
        if tool_name == "Nikto":
            if "x-frame-options" in line_lower:
                f.write("      => PHÂN TÍCH (THẤP): Thiếu Header X-Frame-Options (Nguy cơ Clickjacking).\n")
                f.write("      => KHẮC PHỤC: Thêm 'X-Frame-Options: SAMEORIGIN' vào cấu hình máy chủ web.\n")
            elif "directory indexing found" in line_lower:
                f.write("      => PHÂN TÍCH (TRUNG BÌNH): Lỗi 'Directory Indexing' (liệt kê thư mục) bị bật.\n")
                f.write("      => KHẮC PHỤC: Tắt 'Indexes' trong cấu hình Apache (Options -Indexes).\n")
            elif "outdated" in line_lower and "apache" in line_lower:
                f.write("      => PHÂN TÍCH (CAO): Phiên bản Apache đã lỗi thời (outdated).\n")
                f.write("      => KHẮC PHỤC: Nâng cấp (patch) máy chủ Apache lên phiên bản mới nhất.\n")
            elif "x-content-type-options" in line_lower:
                f.write("      => PHÂN TÍCH (THẤP): Thiếu Header X-Content-Type-Options.\n")
                f.write("      => KHẮC PHỤC: Thêm 'X-Content-Type-Options: nosniff' vào cấu hình máy chủ.\n")
                
        if tool_name == "Nmap":
            if "openssh" in line_lower and any(v in line_lower for v in ["6.6", "5.", "4."]):
                f.write("      => PHÂN TÍCH (CAO): Phiên bản OpenSSH đã quá cũ.\n")
                f.write("      => KHẮC PHỤC: Nâng cấp dịch vụ SSH lên phiên bản mới nhất.\n")
            elif "nse script" in line_lower and "vulnerable" in line_lower:
                f.write("      => PHÂN TÍCH (NGHIÊM TRỌNG): Nmap Scripting Engine (NSE) xác nhận 'VULNERABLE'.\n")
                f.write("      => KHẮC PHỤC: Đọc kỹ thông tin script bên trên và tìm bản vá (patch) ngay.\n")


# --- Hàm tạo báo cáo TXT ---
def generate_combined_report(targets, profile, timestamp, scan_dir):
    """
    Tạo một file báo cáo TXT duy nhất cho TẤT CẢ các mục tiêu.
    """
    report_file_path = f"{scan_dir}/REPORT_TONG_HOP_{timestamp}.txt"
    print(f"[INFO] Đang tạo báo cáo kỹ thuật tổng hợp tại: {report_file_path}")
    
    try:
        full_report_content = "" # Dùng để gửi cho AI
        
        with open(report_file_path, 'w', encoding='utf-8') as f:
            
            for target in targets:
                f.write("\n" + "="*60 + "\n")
                f.write(f" BÁO CÁO MỤC TIÊU: {target.target_str}\n")
                f.write(f" PROFILE ĐÃ CHẠY: {profile.upper()}\n")
                f.write(f" THỜI GIAN QUÉT: {timestamp}\n")
                f.write("="*60 + "\n")
                
                if not target.results:
                    f.write("\nKhông có kết quả nào được thu thập cho mục tiêu này.\n")
                    continue
                
                # Sắp xếp module theo thứ tự Giai đoạn
                # (Chúng ta cần giúp hàm này biết 'tag' của module là gì)
                # Đây là cách đơn giản:
                PHASE_ORDER = {'recon': 1, 'network': 2, 'web': 3, 'exploit_prep': 4}
                
                sorted_module_names = sorted(
                    target.results.keys(), 
                    key=lambda m_name: PHASE_ORDER.get(target.get_module_tag_by_name(m_name), 99)
                )

                for module_name in sorted_module_names:
                    findings = target.results[module_name]
                    f.write(f"\n\n--- KẾT QUẢ TỪ MODULE: {module_name.upper()} ---\n")
                    if findings:
                        write_findings_with_analysis(f, findings, module_name)
                    else:
                        f.write("Không tìm thấy kết quả.\n")
            
            f.flush()
            
        # Đọc lại nội dung vừa ghi để chuẩn bị gửi cho AI
        with open(report_file_path, 'r', encoding='utf-8') as f:
            full_report_content = f.read()
            
        return report_file_path, full_report_content

    except IOError as e:
        print(f"[LỖI] Không thể ghi file báo cáo. Lỗi: {e}")
        return None, None


# --- (Các hàm AI không đổi) ---
def get_ai_summary(report_content):
    if not AI_AVAILABLE:
        return "Bản tóm tắt AI bị tắt (thiếu 'google-generativeai' hoặc API Key)."

    print(f"[INFO] Đang gửi báo cáo đến Gemini API để tạo tóm tắt chi tiết...")
    API_KEY = os.getenv("GEMINI_API_KEY")
    if not API_KEY:
        return "Bản tóm tắt AI bị tắt (thiếu GEMINI_API_KEY)."
    try:
        genai.configure(api_key=API_KEY)
        model = genai.GenerativeModel('gemini-flash-latest') 
    except Exception as e:
        return f"[LỖI] Cấu hình Gemini thất bại: {e}"

    prompt = f"""
    Bạn là một Chuyên gia Phân tích An ninh mạng (Security Analyst) đang
    viết báo cáo "Tóm tắt Kỹ thuật" cho quản lý kỹ thuật và lập trình viên.

    DƯỚI ĐÂY LÀ BÁO CÁO KỸ THUẬT THÔ:
    ---
    {report_content}
    ---

    NHIỆM VỤ CỦA BẠN:
    Viết một "Tóm tắt Kỹ thuật chi tiết" bằng Tiếng Việt, tuân thủ các
    quy tắc sau:
    1. Bắt đầu bằng "Tóm tắt Kỹ thuật chi tiết:".
    2. Xác định các phát hiện bảo mật (findings) quan trọng nhất từ báo cáo.
    3. Với MỖI phát hiện, hãy trình bày rõ ràng:
       - **Phát hiện:** Mô tả vấn đề là gì?
       - **Bằng chứng (Reference):** Tham chiếu chính xác đến bằng chứng kỹ thuật.
       - **Rủi ro:** Giải thích rủi ro kỹ thuật cụ thể.
       - **Khắc phục:** Đề xuất hành động kỹ thuật cụ thể để vá lỗi.
    4. Sử dụng gạch đầu dòng chi tiết và định dạng markdown rõ ràng.
    """
    
    try:
        response = model.generate_content(prompt,
                                          safety_settings={'HARM_CATEGORY_HARASSMENT': 'BLOCK_NONE',
                                                           'HARM_CATEGORY_HATE_SPEECH': 'BLOCK_NONE',
                                                           'HARM_CATEGORY_SEXUALLY_EXPLICIT': 'BLOCK_NONE',
                                                           'HARM_CATEGORY_DANGEROUS_CONTENT': 'BLOCK_NONE'})
        return response.text
    except Exception as e:
        print(f"[LỖI] Gọi Gemini API thất bại: {e}")
        return f"[Lỗi khi tạo tóm tắt AI: {e}]"

def prepend_ai_summary_to_report(report_file_path, ai_summary):
    print(f"[INFO] Đang thêm tóm tắt AI vào đầu file báo cáo...")
    try:
        with open(report_file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        with open(report_file_path, 'w', encoding='utf-8') as f:
            f.write("===========================================\n")
            f.write("     BẢN TÓM TẮT KỸ THUẬT (AI)\n")
            f.write("===========================================\n\n")
            f.write(ai_summary)
            f.write("\n\n===========================================\n")
            f.write("     CHI TIẾT BÁO CÁO KỸ THUẬT\n")
            f.write("===========================================\n")
            f.write(original_content)
        
        print("[OK] Đã thêm tóm tắt AI vào báo cáo.")
    except Exception as e:
        print(f"[LỖI] Không thể ghi tóm tắt AI vào file. Lỗi: {e}")