from setuptools import setup

setup(
    name='salesforce',
    version='0.1',
    packages=['salesforce'],
    url='https://www.abiresearch.com',
    license='',
    author='Peter Baehr',
    author_email='baehr@abiresearch.com',
    description='Wrapper and authentication for the Salesforce API',
    install_requires=[
        'requests==2.18.4',
        'pycrypto==2.6.1',
        'six==1.10.0'
    ]
)
