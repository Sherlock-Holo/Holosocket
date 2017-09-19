from setuptools import setup, find_packages

setup(
    name='Holosocket',
    version='0.1',
    author='Sherlock Holo',
    author_email='sherlockya@gmail.com',
    license='MPL',
    keywords='proxy',
    url='https://github.com/Sherlock-Holo/Holosocket',
    zip_safe=True,

    packages=find_packages(),
    install_requires=[
        'setuptools',
        'pycryptodomex',
        'pyYAML',
        'aiodns'
    ],
    extras_require={
        'uvloop': [],
        'cachetools': []
    },
    entry_points={
        'console_scripts': [
            'wslocal = holosocket.wslocal:main',
            'wsserver = holosocket.wsserver:main'
        ]
    },

    classifiers=[
        'Environment :: Console',
        'License :: OSI Approved :: MPL License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6'
    ]
)
