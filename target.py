#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Target:
    """
    Lớp này đại diện cho MỘT mục tiêu quét (IP hoặc Domain).
    Nó sẽ lưu trữ tất cả thông tin và kết quả cho mục tiêu đó.
    """
    def __init__(self, target_str):
        self.target_str = target_str.strip() # IP hoặc domain gốc
        self.ip = None                 # Sẽ được Nmap cập nhật
        self.web_urls = []             # Sẽ được Nmap cập nhật (ví dụ: http://ip:80)
        self.ssl_ports = []            # Sẽ được Nmap cập nhật
        
        self.project_dir = "" 
        
        # Nơi lưu trữ tất cả kết quả (dạng string)
        # self.results["Nmap"] = ["Cổng 22 mở..."]
        # self.results["WhatWeb"] = ["Apache/2.4.7..."]
        self.results = {}
        
        # (MỚI v1.4) Lưu trữ các đối tượng module đã chạy trên target này
        # Dùng để lấy 'tag' khi sắp xếp báo cáo
        self.executed_modules = {} 

    def add_result(self, module_name, findings_list):
        """
        Thêm kết quả từ một module (ví dụ: "Nmap") vào mục tiêu.
        """
        if module_name not in self.results:
            self.results[module_name] = []
        
        self.results[module_name].extend(findings_list)
    
    def add_executed_module(self, module_name, module_tag):
        """
        Lưu lại tag của module đã chạy để sắp xếp báo cáo.
        """
        if module_name not in self.executed_modules:
            self.executed_modules[module_name] = module_tag

    def get_module_tag_by_name(self, module_name, default_priority=99):
        """
        Lấy 'tag' của một module (ví dụ: 'network')
        để sắp xếp thứ tự trong báo cáo.
        """
        tag_to_priority = {'recon': 1, 'network': 2, 'web': 3, 'exploit_prep': 4}
        tag = self.executed_modules.get(module_name)
        return tag_to_priority.get(tag, default_priority)

    def __str__(self):
        return f"Target({self.target_str})"