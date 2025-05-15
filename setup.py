from setuptools import setup, find_packages

setup(
    name="oli-python",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'web3>=6.0.0',
        'eth-abi>=4.0.0',
        'eth-account>=0.8.0',
        'eth-keys>=0.4.0',
        'requests>=2.25.0',
        'pyyaml>=6.0',
    ],
    author="OLI Contributors",
    author_email="info@openlabels.xyz",
    description="Python client for the Open Labels Initiative",
    long_description=open("README.md", encoding="utf-8").read() if open("README.md", "r", encoding="utf-8") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/openlabelsinitiative/oli-python",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
)