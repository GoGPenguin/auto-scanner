from setuptools import setup, find_packages

setup(
    name="auto_scanner",
    version="1.6.0", # Nâng cấp lên v1.6
    packages=find_packages(), 
    
    install_requires=[
        "google-generativeai",
        "python-whois",
        "elasticsearch", # (MỚI) Thư viện kết nối ELK
    ],
    
    entry_points={
        "console_scripts": [
            "auto_scanner = auto_scanner.main:main",
        ],
    },
    
    author="Nguyen Van Truong Son",
    description="Framework tu dong quet va phan tich lo hong (v1.6 ELK Stack).",
)