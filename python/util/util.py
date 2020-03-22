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
            # print('initial expiration=' + str(self._expiration))
    
        def __call__(self, context, callback):
            #print('__call__ context=' + str(context))
            current = int(time.time())
            expiration = int(self._expiration) - 60 # set the expiration 60 sec before the actual one
            # print('remaining=' + str(expiration - current) + ' expiration=' + str(expiration) + ' current=' + str(current))
            if expiration < current:
                # print('renewing an access token')
                self.get_access_token()
                valid_for = int(self._expiration) - int(time.time())
                # print('new expiration=' + str(self._expiration) + ' valid for ' + str(valid_for) + ' sec')
            metadata = (('authorization', 'Bearer {}'.format(self._access_token)),('bluemix-instance', '{}'.format(self._credentials['Instance'])),)
            #print('metadata=' + str(metadata))
            callback(metadata, None)

        def get_access_token(self):
            # print("*** get a new access token for an HPCS instance on IBM Cloud ***")
        
            # print("APIKEY=" + self._credentials['APIKey'])
            # print("INSTANCE_ID=" + self._credentials['Instance'])
            # print("ENDPOINT=" + self._credentials['Endpoint'])

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
                # print('response=' + json.dumps(resp, indent=4))
                self._expiration = resp['expiration']
                self._access_token = resp['access_token']
                # print('access_token=' + 'xxxxxxxxxxxxxxxxxxxxxxxxx...')
                return self._access_token
        
            except Exception as e:
                print('an unexpected response from IAM_ENDPOINT=' + self._endpoint)
                print('response=' + str(resp_str))
                print(e)
                import traceback
                traceback.print_exc()
                return None
        
    

