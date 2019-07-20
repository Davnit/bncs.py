#!/usr/bin/env python3

from setuptools import setup


setup(
    name='bncs.py',
    version='0.2',
    description='Python library for classic Battle.net client development.',
    author='Davnit',
    author_email='david@davnit.net',
    url='https://github.com/Davnit/bncs.py',
    packages=['bncs', 'bnftp', 'bnls', 'botnet', 'capi'],
    install_requires=['pefile', 'signify'],
    python_requires='>=3.7'
)
