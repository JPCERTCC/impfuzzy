#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, Extension


setup(
    name="pyimpfuzzy",
    version="0.5",
    author="JPCERT/CC Analysis Center",
    author_email="aa-info@jpcert.or.jp",
    license="the GNU General Public License version 2",
    description="Python modules for impfuzzy",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    ext_modules=[Extension(
        "impfuzzyutil",
        sources=["impfuzzy_util.c"],
        libraries=["fuzzy"],
        library_dirs=["/usr/local/lib/", ],
        include_dirs=["/usr/local/include/", ],
    )],
    py_modules=["pyimpfuzzy"],
    url="https://github.com/JPCERTCC/impfuzzy/",
    install_requires=['pefile']
)
