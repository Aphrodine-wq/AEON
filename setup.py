from setuptools import setup, find_packages

setup(
    name="aeon-lang",
    version="0.5.0",
    description="AEON — AI-Native Programming Language & Compiler",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        # Core CLI has no external dependencies — all stdlib + aeon internals.
        # z3, llvmlite, javalang etc. are imported behind try/except guards.
    ],
    extras_require={
        "z3": [
            "z3-solver>=4.12.0",
        ],
        "llvm": [
            "llvmlite>=0.41.0",
        ],
        "java": [
            "javalang>=0.13.0",
        ],
        "dashboard": [
            "flask>=3.0.0",
            "plotly>=5.0.0",
        ],
        "fvaas": [
            "flask>=3.0.0",
            "flask-limiter>=3.0.0",
            "PyJWT>=2.0.0",
        ],
        "full": [
            "z3-solver>=4.12.0",
            "llvmlite>=0.41.0",
            "javalang>=0.13.0",
            "flask>=3.0.0",
            "flask-limiter>=3.0.0",
            "plotly>=5.0.0",
            "PyJWT>=2.0.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "hypothesis>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "aeon=aeon.cli:main",
        ],
    },
)
