"""Compatibility shim so older pip/setuptools can install monocle in editable
mode. Modern installs can rely on pyproject.toml; metadata is kept here so it
works across toolchain versions."""
from setuptools import setup, find_packages

setup(
    name="monocle-re",
    version="0.1.0",
    description="A monocle for stripped binaries — capstone/pyelftools static "
                "analysis for protocol-parser bug hunting",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    python_requires=">=3.8",
    packages=find_packages(include=["monocle*"]),
    install_requires=["capstone>=5.0", "pyelftools>=0.29"],
    entry_points={"console_scripts": ["monocle = monocle.cli:main"]},
)
