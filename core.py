#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import importlib
import pkgutil
from datetime import datetime
from .target import Target
import auto_scanner.modules 
from auto_scanner.report import generate_combined_report, get_ai_summary, prepend_ai_summary_to_report
import concurrent.futures

class ScannerEngine:
    """
    Bộ não (Engine) chính của chương trình.
    (v1.5: Hỗ trợ --timeout và --tool-args)
    """
    
    def __init__(self, args):
        self.args = args
        self.profile = args.profile
        self.use_ai_summary = args.ai_summary
        self.max_workers = args.workers
        self.global_timeout = args.timeout # (MỚI v1.5)
        
        # (MỚI v1.5) Logic chọn module
        self.specific_tools_to_run = None
        self.steps_to_run = ['recon', 'network', 'web', 'exploit_prep'] # Mặc định
        
        if args.tools:
            self.specific_tools_to_run = args.tools.split(',')
        elif args.steps:
            self.steps_to_run = args.steps.split(',')
            
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.modules = {} 
        self.targets = []
        self.scan_dir = "results"
        os.makedirs(self.scan_dir, exist_ok=True)
        
        # (MỚI v1.5) Phân tích (parse) --tool-args
        self.tool_args = {}
        if args.tool_args:
            print("[INFO] Đang phân tích tham số tùy chỉnh (--tool-args)...")
            for arg_str in args.tool_args:
                try:
                    # Tách chuỗi tại dấu ':' đầu tiên
                    tool_name, tool_arg = arg_str.split(':', 1)
                    self.tool_args[tool_name.strip()] = tool_arg.strip()
                    print(f"  [+] Tham số cho '{tool_name}': {tool_arg.strip()}")
                except ValueError:
                    print(f"[LỖI] Tham số '{arg_str}' sai định dạng. Bỏ qua.")
                    print("       Định dạng đúng: \"ToolName: <args>\"")
        
    def load_modules(self):
        # (Không thay đổi so với v1.4)
        print("[INFO] Đang tải (loading) các module quét...")
        base_module_path = auto_scanner.modules.__path__[0]
        phase_dirs = [d for d in os.listdir(base_module_path) if 
                      os.path.isdir(os.path.join(base_module_path, d)) and 
                      not d.startswith('__')]
        
        for phase in phase_dirs:
            if phase == 'export': continue
            self.modules[phase] = []
            phase_path = os.path.join(base_module_path, phase)
            for (_, module_name, _) in pkgutil.iter_modules([phase_path]):
                module_import = importlib.import_module(f"auto_scanner.modules.{phase}.{module_name}")
                for attribute_name in dir(module_import):
                    Attribute = getattr(module_import, attribute_name)
                    try:
                        if (isinstance(Attribute, type) and 
                            issubclass(Attribute, auto_scanner.modules.base_module.BaseModule) and
                            Attribute.name != "Base Module"):
                            self.modules[phase].append(Attribute(self))
                            print(f"[OK] Đã tải module: {Attribute.name} (Giai đoạn: {phase})")
                    except (TypeError, AttributeError):
                        continue 
        print(f"[INFO] Đã tải thành công các module.\n")

    def load_targets(self):
        # (Không thay đổi)
        print("[INFO] Đang tải (loading) mục tiêu...")
        if self.args.target:
            self.targets.append(Target(self.args.target))
        elif self.args.target_list:
            try:
                with open(self.args.target_list, 'r') as f:
                    for line in f:
                        if line.strip():
                            self.targets.append(Target(line.strip()))
                print(f"[INFO] Đã tải {len(self.targets)} mục tiêu từ file {self.args.target_list}.")
            except FileNotFoundError:
                print(f"[LỖI] Không tìm thấy file mục tiêu: {self.args.target_list}")
                exit(1)
        if not self.targets:
            print("[LỖI] Không có mục tiêu nào được cung cấp. (Dùng -t hoặc -iL).")
            exit(1)
        print(f"[INFO] Tổng số mục tiêu cần quét: {len(self.targets)}\n")

    def _run_module_task(self, module, target):
        """
        (MỚI v1.5) Hàm "worker", được cập nhật để truyền
        tham số tùy chỉnh (tool_args) và global_timeout.
        """
        try:
            target.project_dir = os.path.join(self.scan_dir, target.target_str.replace('/', '_').replace(':', '_'))
            os.makedirs(target.project_dir, exist_ok=True)
            
            # Lấy tham số tùy chỉnh cho module này (nếu có)
            custom_args = self.tool_args.get(module.name)
            
            if module.pre_run_check(target, self.profile):
                print(f"[START] Đang chạy {module.name} trên {target.target_str}...")
                module.run(target, 
                           self.profile, 
                           self.timestamp, 
                           tool_args=custom_args, # <-- (MỚI v1.5)
                           default_timeout=self.global_timeout # <-- (MỚI v1.5)
                           )
                print(f"[DONE] Hoàn tất {module.name} trên {target.target_str}.")
            else:
                print(f"[SKIP] Bỏ qua {module.name} cho {target.target_str} (Điều kiện không đạt).")
                
        except Exception as e:
            print(f"[CRASH] Module {module.name} bị crash khi quét {target.target_str}. Lỗi: {e}")

    def start_scan(self):
        # (Không thay đổi so với v1.4)
        print("--- BẮT ĐẦU QUÁ TRÌNH QUÉT ---")

        if self.specific_tools_to_run:
            print(f"[INFO] Chế độ quét: Tool cụ thể ({self.specific_tools_to_run})")
            modules_to_run = []
            for phase_modules in self.modules.values():
                for module in phase_modules:
                    if module.name in self.specific_tools_to_run:
                        modules_to_run.append(module)
            if not modules_to_run:
                print("[LỖI] Không tìm thấy tool nào khớp với tên bạn chọn.")
                return

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for module in modules_to_run:
                    for target in self.targets:
                        futures.append(executor.submit(self._run_module_task, module, target))
                concurrent.futures.wait(futures)
        
        else:
            print(f"[INFO] Chế độ quét: Theo giai đoạn ({self.steps_to_run})")
            for step in self.steps_to_run:
                print(f"\n--- BẮT ĐẦU GIAI ĐOẠN: [{step.upper()}] ---")
                modules_to_run = self.modules.get(step) 
                if not modules_to_run:
                    print(f"[INFO] Không có module nào cho giai đoạn '{step}'. Bỏ qua.")
                    continue

                if step in ['recon', 'network', 'exploit_prep']:
                    print(f"[INFO] Giai đoạn '{step}' đang chạy TUẦN TỰ (Sequential)...")
                    for module in modules_to_run:
                        for target in self.targets:
                            self._run_module_task(module, target)
                else: 
                    print(f"[INFO] Giai đoạn '{step}' đang chạy SONG SONG (Parallel) với {self.max_workers} luồng...")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                        futures = []
                        for module in modules_to_run:
                            for target in self.targets:
                                futures.append(executor.submit(self._run_module_task, module, target))
                        concurrent.futures.wait(futures)

        print("\n--- HOÀN TẤT TẤT CẢ GIAI ĐOẠN QUÉT ---")

    def generate_final_report(self):
        # (Không thay đổi)
        print("\n--- BẮT ĐẦU MODULE 5: TỔNG HỢP BÁO CÁO KỸ THUẬT ---")
        
        report_file_path, full_report_content = generate_combined_report(
            self.targets, 
            self.profile, 
            self.timestamp, 
            self.scan_dir 
        )
        if not report_file_path:
            print("[LỖI] Tạo báo cáo thất bại.")
            return

        print("\n--- BẮT ĐẦU MODULE 6: TẠO TÓM TẮT BẰNG AI ---")
        if self.use_ai_summary:
            if not os.getenv("GEMINI_API_KEY"):
                print("[WARN] Bạn đã bật --ai-summary, nhưng không tìm thấy GEMINI_API_KEY.")
                print("       Bỏ qua bước tóm tắt AI.")
            else:
                ai_summary = get_ai_summary(full_report_content)
                prepend_ai_summary_to_report(report_file_path, ai_summary)
        else:
            print("[INFO] Bản tóm tắt AI bị bỏ qua (do người dùng không yêu cầu).")
            
        print(f"\n[DONE] Toàn bộ quy trình quét đã hoàn tất.")
        print(f"Kiểm tra báo cáo đầy đủ tại: {report_file_path}")