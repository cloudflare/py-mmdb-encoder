#!/usr/bin/env python
from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='py-mmdb-encoder',
    version='1.0.0',
    description='Python MMDB encoder',

    url='https://github.com/cloudflare/py-mmdb-encoder',

    author='Louis Poinsignon / Cloudflare',
    author_email='louis@cloudflare.com',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        'License :: ? :: ?',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    keywords='maxmind geoip network geolocation database tree development',

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),

    project_urls={
        'Bug Reports': 'https://github.com/cloudflare/py-mmdb-encoder/issues',
        'Source': 'https://github.com/cloudflare/py-mmdb-encoder/',
    },
)