from setuptools import setup, find_packages

setup(
    name='Hash_Extender',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'lenext = hash_extender.Length_Extender:main'
        ],
    },
    data_files=[('/usr/bin', ['hash_extender/Length_Extender.py'])],  
)