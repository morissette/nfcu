from setuptools import find_packages, setup

setup(
    name='nfcu',
    packages=find_packages(),
    version='0.3.0',
    description='Navy Federal Credit Union Module',
    author='Marie Harris',
    author_email='marie@cloudista.org',
    url='https://github.com/morissette/nfcu',
    download_url='https://github.com/morissette/nfcu/tarball/0.3.0',
    keywords=['nfcu', 'fintech', 'navy federal', 'api'],
    python_requires='>=3.10',
    install_requires=['requests>=2.32.0'],
    classifiers=[],
)
