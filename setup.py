from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="vulnscan-framework",
    version="1.0.0",
    author="VulnScan Contributors",
    description="Automated Penetration Testing & Vulnerability Scanning Framework with ML",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/vulnscan-framework",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "vulnscan=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    keywords="penetration-testing vulnerability-scanner security recon web-security",
    project_urls={
        "Bug Reports": "https://github.com/your-org/vulnscan-framework/issues",
        "Source": "https://github.com/your-org/vulnscan-framework",
    },
)
