from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
from Cython.Build import cythonize
import os
import sysconfig

class CustomBuildExt(build_ext):
    def build_extension(self, ext):
        python_lib = sysconfig.get_config_var('LIBDIR')
        python_version = sysconfig.get_config_var('LDVERSION')
        
        ext.libraries = [f'python{python_version}', 'secp256k1', 'crypto']
        ext.library_dirs.extend(['/usr/local/lib', python_lib])
        ext.runtime_library_dirs = ['/usr/local/lib']
        ext.include_dirs.extend([sysconfig.get_path('include')])
        super().build_extension(ext)

extensions = [
    Extension(
        "common.common.u2sso.u2sso",
        ["common/common/u2sso/u2sso.pyx"],
        include_dirs=['/usr/local/include'],
        extra_compile_args=['-std=c99']
    )
]

setup(
    name='common',
    package_dir={'': '.'},
    packages=['common', 'common.common', 'common.common.u2sso'],
    ext_modules=cythonize(extensions, language_level=3),
    cmdclass={'build_ext': CustomBuildExt}
)