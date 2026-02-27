from setuptools import find_packages, setup

setup(
    name='nfcu',
    packages=find_packages(),
    version='0.1.2',
    description='Navy Federal Credit Union Module',
    author='Matthew Harris',
    author_email='matt@x-qa.com',
    url='https://github.com/morissette/nfcu',
    download_url='https://github.com/morissette/nfcu/tarball/0.1.2',
    keywords=['nfcu', 'fintech', 'navy federal', 'api'],
    python_requires='>=3.10',
    install_requires=['requests>=2.32.0'],
    classifiers=[],
)
