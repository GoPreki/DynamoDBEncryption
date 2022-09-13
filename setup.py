#!/usr/bin/env python3

from distutils.core import setup

setup(
    name='dynamodb-encryption',
    version='1.0.0',
    author='Preki',
    author_email='david@preki.com',
    packages=['dynamodb_encryption'],
    url='https://preki.com',
    download_url='https://github.com/GoPreki/DynamoDBEncryption',
    license='MIT',
    description='Python library for handling DynamoDB encryption/decryption operations using KMS',
    long_description='Python library for handling DynamoDB encryption/decryption operations using KMS',
    install_requires=[
        'dynamodb-encryption-sdk==3.0.0',
        'boto3>=1.12.32,<=1.23.32'
    ],
)
