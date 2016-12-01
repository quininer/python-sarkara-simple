from setuptools import setup
from rust_ext import build_rust_cmdclass, install_lib_including_rust

setup(name='libsarkara',
    version='0.1.0',
    cmdclass={
        'build_rust': build_rust_cmdclass('libsarkara/Cargo.toml'),
        'install_lib': install_lib_including_rust
    },
    packages=['libsarkara'],
    zip_safe=False
)
