from setuptools import setup

setup(
    name='cfgv',
    description=(
        'Validate configuration and produce human readable error messages.'
    ),
    url='https://github.com/asottile/cfgv',
    version='0.0.2',
    author='Anthony Sottile',
    author_email='asottile@umich.edu',
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
    install_requires=['six'],
    py_modules=['cfgv'],
)
