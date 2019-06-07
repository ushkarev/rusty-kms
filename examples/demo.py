#!/usr/bin/env python3
import datetime
import os
import unittest

import boto3
from botocore.exceptions import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key


class RustyKMS(unittest.TestCase):
    def setUp(self):
        self.client = boto3.client('kms', endpoint_url='http://127.0.0.1:6767/')

    def tearDown(self):
        del self.client

    def count_keys(self):
        count = 0
        while True:
            response = self.client.list_keys()
            count += len(response['Keys'])
            if not response.get('NextMarker'):
                break
        return count

    @classmethod
    def encrypt(cls, data: bytes, key: bytes) -> bytes:
        backend = default_backend()
        key: RSAPublicKey = load_der_public_key(key, backend)
        sha1 = hashes.SHA1()
        sha1_padding = padding.OAEP(mgf=padding.MGF1(sha1), algorithm=sha1, label=b'')
        return key.encrypt(data, padding=sha1_padding)

    def test_rusty_kms(self):
        initial_key_count = self.count_keys()

        response = self.client.generate_random(NumberOfBytes=120)
        plain_text: bytes = response['Plaintext']
        self.assertEqual(len(plain_text), 120)

        response = self.client.create_key(Description='string', Tags=[{'TagKey': 'Name', 'TagValue': 'py-test'}])
        internal_key: str = response['KeyMetadata']['Arn']
        self.assertIn('eu-west-2', internal_key)

        response = self.client.encrypt(KeyId=internal_key, Plaintext=plain_text)
        cipher_text_1 = response['CiphertextBlob']
        self.assertNotEqual(plain_text, cipher_text_1)

        response = self.client.decrypt(CiphertextBlob=cipher_text_1)
        self.assertEqual(response['Plaintext'], plain_text)
        self.assertEqual(response['KeyId'], internal_key)

        response = self.client.create_key(Description='string', Origin='EXTERNAL')
        self.assertEqual(response['KeyMetadata']['KeyState'], 'PendingImport')
        external_key: str = response['KeyMetadata']['Arn']
        self.assertIn('eu-west-2', external_key)

        with self.assertRaises(ClientError):
            self.client.encrypt(KeyId=external_key, Plaintext=plain_text)

        response = self.client.get_parameters_for_import(
            KeyId=external_key, WrappingAlgorithm='RSAES_OAEP_SHA_1', WrappingKeySpec='RSA_2048'
        )
        import_token = response['ImportToken']
        public_key = response['PublicKey']

        response = self.client.generate_random(NumberOfBytes=32)
        key_material: bytes = response['Plaintext']
        encrypted_key_material = self.encrypt(key_material, public_key)

        response = self.client.import_key_material(
            KeyId=external_key,
            ImportToken=import_token,
            EncryptedKeyMaterial=encrypted_key_material,
            ValidTo=datetime.datetime.now() + datetime.timedelta(days=2),
            ExpirationModel='KEY_MATERIAL_EXPIRES',
        )
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        response = self.client.describe_key(KeyId=external_key)
        self.assertEqual(response['KeyMetadata']['KeyState'], 'Enabled')
        self.assertEqual(response['KeyMetadata']['ExpirationModel'], 'KEY_MATERIAL_EXPIRES')

        response = self.client.re_encrypt(CiphertextBlob=cipher_text_1, DestinationKeyId=external_key)
        cipher_text_2 = response['CiphertextBlob']
        self.assertNotEqual(cipher_text_2, plain_text)
        self.assertNotEqual(cipher_text_2, cipher_text_1)

        response = self.client.decrypt(CiphertextBlob=cipher_text_2)
        self.assertEqual(response['Plaintext'], plain_text)
        self.assertEqual(response['KeyId'], external_key)

        with self.assertRaises(ClientError):
            self.client.delete_imported_key_material(KeyId=internal_key)
        response = self.client.delete_imported_key_material(KeyId=external_key)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        response = self.client.schedule_key_deletion(KeyId=internal_key)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)
        response = self.client.schedule_key_deletion(KeyId=external_key)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        self.assertEqual(self.count_keys(), initial_key_count + 2)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)


if __name__ == '__main__':
    os.environ['AWS_DEFAULT_REGION'] = 'eu-west-2'
    os.environ['AWS_ACCESS_KEY_ID'] = 'AAAAAAAAAAAAAAAAAAAAA'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ'
    unittest.main()
