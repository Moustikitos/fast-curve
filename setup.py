# -*- coding:utf-8 -*-
import os
import sys
from subprocess import call, PIPE

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext
from distutils.command.build_clib import build_clib

try:
    from importlib import machinery
    lib_suffix = machinery.all_suffixes()[-1]
    install_requires = []
except ImportError:
    import imp
    lib_suffix = imp.get_suffixes()[0][0]
    install_requires = ['future']


class build_ctypes(build_ext):

    EXT = ".dll" if sys.platform.startswith("win") else lib_suffix

    def __init__(self, *args, **kw):
        build_clib_options = []
        for long_, short, comment in build_clib.user_options:
            build_clib_options.extend([long_, short])
        call(
            [sys.executable, 'setup.py', 'build_clib'] +
            [arg for arg in sys.argv if arg.lstrip("-") in build_clib_options],
            stdout=PIPE
        )
        build_ext.__init__(self, *args, **kw)

    def build_extension(self, ext):
        return build_ext().build_extension(ext)

    def get_export_symbols(self, ext):
        return ext.export_symbols

    def get_ext_filename(self, ext_name):
        return ext_name + build_ctypes.EXT


if "static" in sys.argv:
    sys.argv.pop(sys.argv.index("static"))
    # configure compilation
    extra_compile_args = ["-Ofast"]
    include_dirs = [os.path.abspath('./src')]
    libraries = []
    if sys.platform.startswith("win"):
        # configuration using mingw compiler from Msys 2.x installed in C:/
        extra_link_args = [
            "-l:libpython%s.%s.a" % sys.version_info[:2],
            "-l:libgmp.a",
            "-static"
        ]
        library_dirs = [r'C:\Msys\usr\lib']
    else:
        extra_link_args = ["-l:libgmp.so"]
        library_dirs = []
else:
    # configure compilation
    extra_compile_args = ['-Ofast']
    include_dirs = [os.path.abspath('./src')]
    libraries = ['gmp']
    extra_link_args = []
    library_dirs = []

# configure libraries
libraries = [
    (
        "ecdsa", {
            "sources": ["src/ecdsa.c"],
            "extra_compile_args": extra_compile_args,
            "extra_link_args": extra_link_args,
            "include_dirs": include_dirs,
            "library_dirs": library_dirs,
            "libraries": libraries,
        }
    ),
    (
        "schnorr", {
            "sources": ["src/schnorr.c", "src/sha256.c"],
            "extra_compile_args": extra_compile_args,
            "extra_link_args": extra_link_args,
            "include_dirs": include_dirs,
            "library_dirs": library_dirs,
            "libraries": libraries,
        }
    )
]

lib_ecdsa, lib_schnorr = libraries

cmd_class = {
    "build_ctypes": build_ctypes,
    "build_ext": build_ctypes
}

ext_modules = [
    Extension('cSecp256k1._ecdsa', **lib_ecdsa[-1]),
    Extension('cSecp256k1._schnorr', **lib_schnorr[-1])
]

with open("VERSION") as f1, open("README.md") as f2:
    VERSION = f1.read().strip()
    LONG_DESCRIPTION = f2.read()

kw = {
    "version": VERSION,
    "name": "cSecp256k1",
    "keywords": ["ctypes", "curve", "bitcoin"],
    "author": "Toons",
    "author_email": "moustikitos@gmail.com",
    "maintainer": "Toons",
    "maintainer_email": "moustikitos@gmail.com",
    "url": "https://github.com/Moustikitos/fast-curve",
    "download_url":
        "https://github.com/Moustikitos/fast-curve/archive/master.zip",
    "include_package_data": True,
    "description": "Fast python implementation for bitcoin curve",
    "long_description": LONG_DESCRIPTION,
    "long_description_content_type": "text/markdown",
    "packages": ["cSecp256k1"],
    "install_requires": install_requires,
    "tests_require": ["pytest", "pytest-benchmark"],
    "libraries": libraries,
    "ext_modules": ext_modules,
    "cmdclass": cmd_class,
    "license": "Copyright 2021, MIT licence",
    "classifiers": [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
    ],
}

setup(**kw)
