"""Setup script for Storage Manager CLI."""

from setuptools import setup, find_packages
from pathlib import Path

# Read requirements
requirements = Path('requirements.txt').read_text().splitlines()

setup(
    name='storage-manager',
    version='2.0.0',
    description='Professional storage analysis and cleanup utility with intelligent junk detection',
    author='Storage Manager Team',
    python_requires='>=3.7',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    package_data={
        'storage_manager': ['data/*.json'],
    },
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'storage-manager=storage_manager.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: System :: Filesystems',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)
