#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class Target:
    """
    Lớp đại diện cho mục tiêu quét.
    (v1.6: Thêm json_results để lưu dữ liệu có cấu trúc cho ELK)
    """
    def __init__(self, target_str):
        self.target_str = target_str.strip()
        self.ip = None
        self.web_urls = []
        self.ssl_ports = []
        self.project_dir = "" 
        
        # Kết quả dạng văn bản (cho báo cáo .txt)
        self.results = {}
        
        # (MỚI v1.6) Kết quả dạng JSON (cho Elasticsearch)
        self.json_results = [] 

        self.executed_modules = {} 

    def add_result(self, module_name, findings_list):
        if module_name not in self.results:
            self.results[module_name] = []
        self.results[module_name].extend(findings_list)

    def add_json_result(self, data_dict):
        """
        (MỚI v1.6) Thêm một bản ghi JSON vào danh sách.
        """
        # Tự động thêm target vào mỗi bản ghi để dễ query
        if 'target' not in data_dict:
            data_dict['target'] = self.target_str
        self.json_results.append(data_dict)
    
    def add_executed_module(self, module_name, module_tag):
        if module_name not in self.executed_modules:
            self.executed_modules[module_name] = module_tag

    def get_module_tag_by_name(self, module_name, default_priority=99):
        tag_to_priority = {'recon': 1, 'network': 2, 'web': 3, 'exploit_prep': 4}
        tag = self.executed_modules.get(module_name)
        return tag_to_priority.get(tag, default_priority)

    def __str__(self):
        return f"Target({self.target_str})"