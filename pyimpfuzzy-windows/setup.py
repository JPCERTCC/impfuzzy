#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, Extension


setup(
    name="pyimpfuzzy-windows",
    version="0.1",
    author="JPCERT/CC Analysis Center",
    author_email="aa-info@jpcert.or.jp",
    license="the GNU General Public License version 2",
    description="impfuzzy python modules for Windows",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages = ["bin"],
    py_modules=["pyimpfuzzy"],
    package_data={"bin": ["*.dll"]},
    url="https://github.com/JPCERTCC/impfuzzy/",
    install_requires=['pefile']
)
