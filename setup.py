import setuptools
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

def parse_requirements(filename):
    """ load requirements from a pip requirements file """
    lineiter = (line.strip() for line in open(filename))
    return [line for line in lineiter if line and not line.startswith("#")]


setuptools.setup(
    name="osas",
    version="0.9.1",
    author="Multiple Authors",
    author_email="boros@adobe.com",
    description="One Stop Anomaly Shop",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/adobe/OSAS/",
    project_urls={
        "Source Code": "https://github.com/adobe/OSAS/",
        "Bug Tracker": "https://github.com/adobe/OSAS/issues",
        "Documentation": "https://github.com/adobe/OSAS/docs/"
    },
    classifiers=[
        "Programming Language :: Python :: 3.0",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages("src"),
    python_requires=">=3.12",
    include_package_data=True,
    install_requires=parse_requirements("requirements.txt"),
    package_dir={"": "src"},
    entry_points = {
        "console_scripts": [
            "osas = osas.cli:main"
        ]
    }
)
