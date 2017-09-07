from setuptools import setup, find_packages

setup(
    name='Holosocket',
    version='0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'wslocal = holosocket.wslocal:main',
            'wsserver = holosocket.wsserver:main'
        ]
    }
)
