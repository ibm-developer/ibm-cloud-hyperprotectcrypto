#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import time, json, asn1
import grpc
from subprocess import check_output

# GetPubkeyBytesFromSPKI extracts a coordinate bit array from the public key in SPKI format
def GetPubkeyBytesFromSPKI(spki):
    decoder = asn1.Decoder()
    try:
        decoder.start(spki)
        decoder.enter()
        decoder.read() # read the initial sequence
        tag, pubkey = decoder.read()
        pubkey_bytearray = bytearray(pubkey)
        pubkey = bytes(pubkey_bytearray[1:]) # drop the first byte
        return pubkey
    except Exception as e:
        print(e)
        return None

class Channel:
    
    def __init__(self, credentials):
        self._authPlugin = self.AuthPlugin(credentials)

    def get_channel(self, address):
        call_credentials = grpc.metadata_call_credentials(self._authPlugin)
        channel_credential = grpc.ssl_channel_credentials()
        composite_credentials = grpc.composite_channel_credentials(channel_credential, call_credentials)
        channel = grpc.secure_channel(address, composite_credentials)
        return channel
        
    class AuthPlugin(grpc.AuthMetadataPlugin):
        
        def __init__(self, credentials):
            self._credentials = credentials
            self._access_token = ''
            self._expiration = int(time.time())
    
        def __call__(self, context, callback):
            #print('__call__ context=' + str(context))
            current = int(time.time())
            expiration = int(self._expiration) - 60 # set the expiration 60 sec before the actual one
            if expiration < current:
                self.get_access_token()

            metadata = (('authorization', 'Bearer {}'.format(self._access_token)),('bluemix-instance', '{}'.format(self._credentials['Instance'])),)
            callback(metadata, None)

        def get_access_token(self):
            apikey = self._credentials['APIKey']
            endpoint = self._credentials['Endpoint']
            cmd = 'curl -sS -k -X POST --header "Content-Type: application/x-www-form-urlencoded" --header "Accept: application/json" --data-urlencode "grant_type=urn:ibm:params:oauth:grant-type:apikey" --data-urlencode "apikey=' + apikey + '" "' + endpoint + '/identity/token"'

            try:
                resp_str = check_output(cmd, shell=True).rstrip().decode('utf8')
            except Exception as e:
                print('an unexpected response from IAM_ENDPOINT=' + endpoint)
                print(e)
                import traceback
                traceback.print_exc()
                return None

            try:
                resp = json.loads(resp_str)
                self._expiration = resp['expiration']
                self._access_token = resp['access_token']
                return self._access_token
        
            except Exception as e:
                print('an unexpected response from IAM_ENDPOINT=' + self._endpoint)
                print('response=' + str(resp_str))
                print(e)
                import traceback
                traceback.print_exc()
                return None
        
    

