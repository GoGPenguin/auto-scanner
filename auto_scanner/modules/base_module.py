#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import shutil 

class BaseModule:
    name = "Base Module"
    def __init__(self, engine):
        self.engine = engine
    def pre_run_check(self, target, profile):
        return True
    def run(self, target, profile, timestamp, tool_args=None, default_timeout=None):
        raise NotImplementedError