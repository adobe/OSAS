import setuptools
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

lib_folder = os.path.dirname(os.path.realpath(__file__))
requirement_path = lib_folder + '/requirements.txt'
install_requires = [] # Here we'll get: ["gunicorn", "docutils>=0.3", "lxml==0.5a7"]
if os.path.isfile(requirement_path):
    with open(requirement_path) as f:
        install_requires = f.read().splitlines()

setuptools.setup(
    name="osas",
    version="0.0.1",
    author="Tiberiu Boros",
    author_email="boros@adobe.com",
    description="One Stop Anomaly Shop",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/adobe/OSAS/",
    project_urls={
        "Bug Tracker": "https://github.com/adobe/OSAS/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3.0",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
    include_package_data=True,
    install_requires=install_requires
)
