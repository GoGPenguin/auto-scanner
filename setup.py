from setuptools import setup, find_packages

setup(
    name="auto_scanner",
    version="1.3.0", # Nâng cấp lên v1.3
    
    # find_packages() sẽ tự động tìm:
    # auto_scanner
    # auto_scanner.modules
    # auto_scanner.modules.recon
    # auto_scanner.modules.network
    # auto_scanner.modules.web
    packages=find_packages(), 
    
    install_requires=[
        "google-generativeai",
        "python-whois",
    ],
    
    entry_points={
        "console_scripts": [
            "auto_scanner = auto_scanner.main:main",
        ],
    },
    
    author="Nguyen Van Truong Son",
    author_email="son72ltv2@gmail.com",
    description="Framework tu dong quet va phan tich lo hong (v1.3 Phased).",
)