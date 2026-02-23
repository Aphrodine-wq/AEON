from setuptools import setup, find_packages

setup(
    name="aeon-lang",
    version="0.5.0",
    description="AEON — AI-Native Programming Language & Compiler",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "llvmlite>=0.41.0",
        "z3-solver>=4.12.0",
    ],
    entry_points={
        "console_scripts": [
            "aeon=aeon.cli:main",
        ],
    },
)
