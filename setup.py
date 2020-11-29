#!/usr/bin/env python3

from setuptools import setup, find_packages


setup(
    name='bncs.py',
    version='0.3',
    description='Python library for classic Battle.net client development.',
    author='Davnit',
    author_email='david@davnit.net',
    url='https://github.com/Davnit/bncs.py',
    packages=find_packages(),
    install_requires=['pefile', 'signify'],
    python_requires='>=3.8'
)
