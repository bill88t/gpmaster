"""Setup script for gpmaster."""

from setuptools import setup, find_packages

setup(
    name="gpmaster",
    version="1.0.0",
    description="GPG-backed lockbox for secrets management",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="GPMaster Contributors",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[
        "python-gnupg>=0.5.0",
        "pyotp>=2.8.0",
    ],
    entry_points={
        "console_scripts": [
            "gpmaster=gpmaster.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
)
