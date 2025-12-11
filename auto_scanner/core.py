#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import importlib
import pkgutil
from datetime import datetime
from .target import Target
import auto_scanner.modules 
from auto_scanner.report import generate_combined_report, get_ai_summary, prepend_ai_summary_to_report, export_to_elasticsearch
import concurrent.futures

class ScannerEngine:
    def __init__(self, args):
        self.args = args
        self.profile = args.profile
        self.use_ai_summary = args.ai_summary
        self.max_workers = args.workers
        self.global_timeout = args.timeout
        
        self.specific_tools_to_run = None
        self.steps_to_run = ['recon', 'network', 'web', 'exploit_prep', 'export']
        
        if args.tools:
            self.specific_tools_to_run = args.tools.split(',')
        elif args.steps:
            self.steps_to_run = args.steps.split(',')
            
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.modules = {} 
        self.targets = []
        self.scan_dir = "results"
        os.makedirs(self.scan_dir, exist_ok=True)
        
        self.tool_args = {}
        if args.tool_args:
            for arg_str in args.tool_args:
                try:
                    name, arg = arg_str.split(':', 1)
                    self.tool_args[name.strip()] = arg.strip()
                except: pass

    def load_modules(self):
        print("[INFO] Loading modules...")
        base = auto_scanner.modules.__path__[0]
        for phase in os.listdir(base):
            if phase.startswith('__') or not os.path.isdir(os.path.join(base, phase)): continue
            if phase == 'export': continue
            self.modules[phase] = []
            for (_, name, _) in pkgutil.iter_modules([os.path.join(base, phase)]):
                mod = importlib.import_module(f"auto_scanner.modules.{phase}.{name}")
                for attr in dir(mod):
                    cls = getattr(mod, attr)
                    if isinstance(cls, type) and hasattr(cls, 'name') and cls.name != "Base Module":
                        self.modules[phase].append(cls(self))

    def load_targets(self):
        if self.args.target: self.targets.append(Target(self.args.target))
        elif self.args.target_list:
            with open(self.args.target_list) as f:
                for line in f:
                    if line.strip(): self.targets.append(Target(line.strip()))

    def _run_module_task(self, module, target):
        try:
            target.project_dir = os.path.join(self.scan_dir, target.target_str.replace('/', '_'))
            os.makedirs(target.project_dir, exist_ok=True)
            custom_args = self.tool_args.get(module.name)
            
            if module.pre_run_check(target, self.profile):
                print(f"[START] {module.name} -> {target.target_str}")
                module.run(target, self.profile, self.timestamp, tool_args=custom_args, default_timeout=self.global_timeout)
                target.add_executed_module(module.name, getattr(module, 'tag', 'unknown'))
                print(f"[DONE] {module.name}")
            else:
                print(f"[SKIP] {module.name}")
        except Exception as e:
            print(f"[CRASH] {module.name}: {e}")

    def start_scan(self):
        print("--- STARTING SCAN ---")
        if self.specific_tools_to_run:
            print(f"[INFO] Chạy tools: {self.specific_tools_to_run}")
            # Tìm và gom module
            mods_to_run = []
            for phase_mods in self.modules.values():
                for m in phase_mods:
                    if m.name in self.specific_tools_to_run: mods_to_run.append(m)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = [ex.submit(self._run_module_task, m, t) for m in mods_to_run for t in self.targets]
                concurrent.futures.wait(futures)
        else:
            for step in self.steps_to_run:
                print(f"\n--- PHASE: {step.upper()} ---")
                if step == 'export':
                    export_to_elasticsearch(self.targets)
                    continue
                
                mods = self.modules.get(step)
                if not mods: continue

                if step in ['recon', 'network', 'exploit_prep']:
                    for m in mods:
                        for t in self.targets: self._run_module_task(m, t)
                else:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                        futures = [ex.submit(self._run_module_task, m, t) for m in mods for t in self.targets]
                        concurrent.futures.wait(futures)

    def generate_final_report(self):
        path, content = generate_combined_report(self.targets, self.profile, self.timestamp, self.scan_dir)
        if self.use_ai_summary and content:
            summary = get_ai_summary(content)
            prepend_ai_summary_to_report(path, summary)
        print(f"[DONE] Report: {path}")