from setuptools import setup, find_packages

setup(
    name='ssl-certificate-builder',
    version='1.0.0',

    description='Generate SSL certificates from description files',
    url='https://github.com/fkrull/ssl-certificate-builder',
    license='BSD-2-clause',

    packages=find_packages('src'),
    package_dir={'': 'src'},
    install_requires=[
        'jinja2',
        'pyyaml',
    ],

    entry_points={
        'console_scripts': [
            'gen-ssl=ssl_certificate_builder.__main__:main',
        ],
    },
)
