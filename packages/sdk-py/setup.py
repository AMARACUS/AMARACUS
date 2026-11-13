from setuptools import setup, find_packages

setup(
    name="amaracus",
    version="1.0.0",
    description="Official Python SDK for the AMARACUS Cryptographic Developer Platform",
    long_description=open("README.md", "r", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="AMARACUS Engineering",
    author_email="security@amaracus.tech",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
    ],
)
