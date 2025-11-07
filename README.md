# Auto-Scanner Framework (v1.3)

**Tên đề tài:** Xây dựng chương trình trên Kali Linux tự động thực thi các tools quét lỗ hổng

Đây là một framework tự động hóa quy trình đánh giá lỗ hổng, được viết bằng Python cho môi trường Kali Linux. Chương trình này đóng vai trò là một bộ điều phối (orchestrator), tự động gọi các công cụ quét, điều phối chúng theo logic (tuần tự và song song), tổng hợp kết quả, và tạo báo cáo phân tích.

---

## Tính năng chính

* **Kiến trúc Module (OOP):** Dự án được chia thành các module độc lập theo từng giai đoạn (recon, network, web), giúp dễ dàng bảo trì và mở rộng (chỉ cần thêm file vào thư mục module).
* **Thực thi Song song:** Tự động chạy các module quét web (Nikto, Gobuster, WhatWeb...) song song bằng cách sử dụng thread pool (`concurrent.futures`) để tiết kiệm thời gian.
* **Điều khiển Quét Linh hoạt:** Cho phép người dùng chọn quét theo:
    * **Giai đoạn (`--steps`):** Ví dụ: `recon,web`.
    * **Tool cụ thể (`--tools`):** Ví dụ: `Nmap,Nikto`.
* **Hỗ trợ Đa mục tiêu:** Quét một mục tiêu (`-t`) hoặc quét từ danh sách (`-iL`).
* **Profile Quét:** Cung cấp 2 chế độ `fast` (nhanh, 100 cổng) và `detailed` (chậm, 65535 cổng + script `vuln`).
* **Phân tích Báo cáo Lai ghép (Hybrid):**
    1.  **Rule-based:** Tự động chèn phân tích (`=> PHÂN TÍCH:`) cho các lỗi phổ biến.
    2.  **AI-based (Tùy chọn):** Dùng cờ `--ai-summary` để gọi Gemini API và tạo tóm tắt kỹ thuật chi tiết.
* **Đóng gói Chuyên nghiệp:** Sử dụng `setuptools` (`setup.py`) để cài đặt chương trình như một lệnh (`auto_scanner`) trong môi trường ảo.
* **Triển khai Tự động:** Cung cấp file cấu hình `systemd` (`.service`, `.timer`) để lập lịch chạy quét tự động.

---

## Yêu cầu

### 1. Công cụ Hệ thống (APT)

Chương trình này yêu cầu các công cụ sau phải được cài đặt trên hệ thống Kali Linux:

```bash
sudo apt update
sudo apt install nmap nikto gobuster whois sslscan dmitry whatweb wafw00f uniscan skipfish
2. Thư viện Python (PIP)
Các thư viện Python cần thiết được liệt kê trong setup.py và sẽ được cài đặt tự động.

google-generativeai
python-whois

Hướng dẫn cài đặt và chạy
Bước 1: Chuẩn bị môi trường


# 1. Clone dự án (nếu dùng git)
# git clone [URL_DU_AN]
# cd [THU_MUC_DU_AN]

# 2. Tạo môi trường ảo (venv)
python3 -m venv venv

# 3. Kích hoạt venv
source venv/bin/activate
Bước 2: Cài đặt Gói (Package)
Sử dụng pip để cài đặt chương trình (ở chế độ "editable", có thể chỉnh sửa code):



# (Đảm bảo bạn đang ở trong venv và ở thư mục gốc có file setup.py)
pip install -e .
Lệnh này sẽ cài đặt các thư viện Python cần thiết và tạo lệnh auto_scanner trong venv của bạn.

Bước 3: (Tùy chọn) Cài đặt API Key
Nếu bạn muốn dùng tính năng --ai-summary, hãy đặt biến môi trường:



export GEMINI_API_KEY="AIzaSy...dqE"
Bước 4: Chạy Chương trình
Sau khi cài đặt, bạn có thể gọi auto_scanner như một lệnh:

Quét cơ bản (1 target, profile nhanh):



auto_scanner -t scanme.nmap.org
Quét nâng cao (từ file, profile chi tiết, có tóm tắt AI):



auto_scanner -iL targets.txt -p detailed --ai-summary
Quét theo Giai đoạn (chỉ chạy network và web):



auto_scanner -t scanme.nmap.org --steps network,web
Quét theo Tool Cụ thể (chỉ chạy Nmap và Nikto):



auto_scanner -t scanme.nmap.org --tools Nmap,Nikto
Quét song song với 20 luồng (thay vì 10):



auto_scanner -iL targets.txt -w 20
Triển khai Tự động (systemd)
Phần này hướng dẫn lập lịch cho auto_scanner tự chạy mỗi ngày.

1. Tạo file .env
Tạo file này ở thư mục home (~) để lưu API Key an toàn:



# Chạy lệnh: nano ~/.env
# Thêm nội dung:
GEMINI_API_KEY=AIzaSy...dqE
2. Tạo file Dịch vụ (.service)
Tạo file tại ~/.config/systemd/user/auto_scanner.service. (Lưu ý: Sửa lại đường dẫn WorkingDirectory và ExecStart nếu của bạn khác)



[Unit]
Description=Chay script Auto Scanner dinh ky
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/home/kali/ATTT
EnvironmentFile=/home/kali/.env
ExecStart=/home/kali/ATNT/venv/bin/auto_scanner -iL /home/kali/ATTT/targets.txt -p fast --ai-summary
3. Tạo file Bộ đếm giờ (.timer)
Tạo file tại ~/.config/systemd/user/auto_scanner.timer.



[Unit]
Description=Bo dem gio cho Auto Scanner

[Timer]
# Chạy vào 2:00 sáng mỗi ngày
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
4. Kích hoạt


# 1. Tải lại systemd
systemctl --user daemon-reload

# 2. Kích hoạt timer (để tự chạy sau khi reboot)
systemctl --user enable auto_scanner.timer

# 3. Khởi động timer
systemctl --user start auto_scanner.timer
Bạn có thể kiểm tra trạng thái bằng systemctl --user status auto_scanner.timer và xem log bằng journalctl --user -u auto_scanner.service.