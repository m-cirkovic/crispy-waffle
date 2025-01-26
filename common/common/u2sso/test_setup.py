from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from Cython.Build import cythonize
import os
import subprocess

class CustomBuildExt(build_ext):
    def build_extension(self, ext):
        ext.libraries = []
        ext.extra_link_args = [
            f'-L{os.path.abspath("crypto-dbpoe/.libs")}',
            f'-Wl,-rpath,{os.path.abspath("crypto-dbpoe/.libs")}',
            '-lsecp256k1',
            '-lssl',
            '-lcrypto'
        ]
        super().build_extension(ext)

extensions = [
    Extension(
        "u2sso",
        ["u2sso.pyx"],
        include_dirs=[
            'crypto-dbpoe/include',
            '/usr/include/openssl'
        ],
        extra_compile_args=['-std=c99'],
        language='c'
    )
]

setup(
    name='u2sso',
    ext_modules=cythonize(extensions, language_level=3),
    cmdclass={'build_ext': CustomBuildExt}
)