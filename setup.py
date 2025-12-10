"""Setup script for isilon-mcp-server package."""
from pathlib import Path
from setuptools import setup, find_packages

# Read long description from README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="isilon-mcp-server",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    packages=find_packages(exclude=["tests*", "dev*"]),
    python_requires=">=3.10",
    long_description=long_description,
    long_description_content_type="text/markdown",
)
