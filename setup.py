# -*- coding:utf-8 -*-
import os
import sys

try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext


with open("VERSION") as f1, open("README.md") as f2:
    VERSION = f1.read().strip()
    LONG_DESCRIPTION = f2.read()


#: to build a pure .so or .dll file to be used within ctypes
class CTypes(Extension):
    pass


class build_ctypes_ext(build_ext):

    def build_extension(self, ext):
        # identify extension type
        self._ctypes = isinstance(ext, CTypes)
        return super().build_extension(ext)

    def get_export_symbols(self, ext):
        if self._ctypes:
            return ext.export_symbols
        return super().get_export_symbols(ext)

    def get_ext_filename(self, ext_name):
        if self._ctypes:
            return ext_name + (
                '.dll' if sys.platform.startswith("win") else ".so"
            )
        return super().get_ext_filename(ext_name)


extra_compile_args = ["-O2"]
if sys.platform.startswith("win"):
    extra_link_args = [
        "-l:libpython%s.%s.dll.a" % sys.version_info[:2],
        "-l:libgmp.a",
        "-static"
    ]
    library_dirs = [
        r'C:\Msys\home\Toons\gmp-6.2.1\.libs',
        r'C:\Msys\usr\lib'
    ]
    include_dirs = [
        os.path.abspath('./src'),
        r'C:\Msys\home\Toons\gmp-6.2.1'
    ]
    libraries = ["libgmp"]
else:
    extra_link_args = []
    library_dirs = []
    include_dirs = [
        os.path.abspath('./src'),
        "/home/toons/libgmp"
    ]
    libraries = []


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
    "description": "Pure python implementation for bitcoin curve",
    "long_description": LONG_DESCRIPTION,
    "long_description_content_type": "text/markdown",
    "packages": ["pySecp256k1", "cSecp256k1"],
    "install_requires": [],
    "ext_modules": [
        CTypes(
            'cSecp256k1.ecdsa',
            extra_compile_args=extra_compile_args,
            extra_link_args=extra_link_args,
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries,
            sources=["src/ecdsa.c", "src/sha256.c"],
        ),
        CTypes(
            'cSecp256k1.schnorr',
            extra_compile_args=extra_compile_args,
            extra_link_args=extra_link_args,
            include_dirs=include_dirs,
            library_dirs=library_dirs,
            libraries=libraries,
            sources=["src/schnorr.c", "src/sha256.c"],
        )
    ],
    "cmdclass": {"build_ext": build_ctypes_ext},
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
