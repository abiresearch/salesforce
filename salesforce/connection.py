import json
import time
from base64 import urlsafe_b64encode

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from six import text_type
import requests


class JwtConnection:
    def __init__(self, consumer_id, username, signing_key_filename):
        jwt_header = {"alg": "RS256"}
        encoded_jwt_header = urlsafe_b64encode(
                text_type(jwt_header).encode('UTF-8'))

        claims_set = {'iss': consumer_id,
                      'sub': username,
                      'aud': 'https://login.salesforce.com',
                      'exp': str(int(time.time()))}

        encoded_claims_set = urlsafe_b64encode(
                text_type(claims_set).encode('UTF-8'))

        jwt_bearer_token = encoded_jwt_header + b'.' + encoded_claims_set

        key = RSA.importKey(open(signing_key_filename, 'rb').read())
        signer = PKCS1_v1_5.new(key)
        signature = urlsafe_b64encode(
                signer.sign(SHA256.new(jwt_bearer_token)))

        signed_jwt_bearer_token = jwt_bearer_token + b'.' + signature

        r = requests.post(
            'https://login.salesforce.com/services/oauth2/token',
            {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
             'assertion': signed_jwt_bearer_token})

        r.raise_for_status()

        self.access_token = r.json()['access_token']

    def _get_headers(self):
        return {'Authorization': 'Bearer %s' % self.access_token,
                'Content-Type': 'application/json'}

    def get(self, url):
        return requests.get(url, headers=self._get_headers())

    def post(self, url, payload):
        return requests.post(url, data=json.dumps(payload),
                             headers=self._get_headers())

    def patch(self, url, payload):
        return requests.patch(url, data=json.dumps(payload),
                              headers=self._get_headers())

    def delete(self, url):
        return requests.delete(url, headers=self._get_headers())

    def head(self, url):
        return requests.head(url, headers=self._get_headers())
