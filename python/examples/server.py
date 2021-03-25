#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import sys
sys.path.extend(['../ep11', '../util'])

import uuid, grep11consts as ep11, server_pb2 as pb, server_pb2_grpc, pkcs11_pb2, grpc
import hashlib, asn1, util

# The following IBM Cloud items need to be changed prior to running the sample program
address = "<grep11_server_address>:<port>"

credentials = {
    'APIKey':   "<ibm_cloud_apikey>",
    'Endpoint': "<https://<iam_ibm_cloud_endpoint>",
    'Instance': "<hpcs_instance_id>"
}

# Example_getMechanismInfo retrieves a mechanism list and retrieves detailed information for the CKM_RSA_PKCS mechanism
# Flow: connect, get mechanism list, get mechanism info
def Example_getMechanismInfo():
    with util.Channel(credentials).get_channel(address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            mechanismListRequest = pb.GetMechanismListRequest()
            mechanismListResponse = cryptoClient.GetMechanismList(mechanismListRequest)
    
            print("Got mechanism list:\n{} ...\n".format(mechanismListResponse.Mechs[:1]))

            mechanismInfoRequest = pb.GetMechanismInfoRequest(Mech=ep11.CKM_RSA_PKCS)
            mechanismInfoResponse = cryptoClient.GetMechanismInfo(mechanismInfoRequest)

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)
            
    # Output:
    # Got mechanism list:
    # [CKM_RSA_PKCS] ...

# Example_encryptAndDecrypt encrypts and decrypts plain text
# Flow: connect, generate AES key, generate IV, encrypt multi-part data, decrypt multi-part data
def Example_encryptAndDecrypt():
    with util.Channel(credentials).get_channel(address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
            keyLen = 128
            template = util.ep11attributes({
                ep11.CKA_VALUE_LEN: int(keyLen/8),
                ep11.CKA_WRAP: False,
                ep11.CKA_UNWRAP: False,
                ep11.CKA_ENCRYPT: True,
                ep11.CKA_DECRYPT: True,
                ep11.CKA_EXTRACTABLE: False, # set to false!
                ep11.CKA_TOKEN: False # ignored by EP11
            })

            r = pb.GenerateKeyRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_KEY_GEN),
                Template=template,
                # KeyId=str(uuid.uuid4()) # optional
            )

            generateKeyStatus = cryptoClient.GenerateKey(r)

            print("Generated AES Key")

            rngTemplate = pb.GenerateRandomRequest(
	        Len=(ep11.AES_BLOCK_SIZE)
	    )
        
            rng = cryptoClient.GenerateRandom(rngTemplate)

            iv = rng.Rnd[:ep11.AES_BLOCK_SIZE]

            print("Generated IV")

            encipherInitInfo = pb.EncryptInitRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, Parameter=iv),
	        Key=generateKeyStatus.Key # you may want to store this
	    )
            cipherStateInit = cryptoClient.EncryptInit(encipherInitInfo)

            plain = b'Hello, this is a very long and creative message without any imagination'

            encipherDataUpdate = pb.EncryptUpdateRequest(
                State=cipherStateInit.State,
                Plain=plain[:20]
            )
            encipherStateUpdate = cryptoClient.EncryptUpdate(encipherDataUpdate)

            ciphertext = encipherStateUpdate.Ciphered
            encipherDataUpdate = pb.EncryptUpdateRequest(
                State=encipherStateUpdate.State,
                Plain=plain[20:]
            )
            encipherStateUpdate = cryptoClient.EncryptUpdate(encipherDataUpdate)

            ciphertext = ciphertext + encipherStateUpdate.Ciphered
            encipherDataFinal = pb.EncryptFinalRequest(
                State=encipherStateUpdate.State
            )
            encipherStateFinal = cryptoClient.EncryptFinal(encipherDataFinal)

            ciphertext = ciphertext + encipherStateFinal.Ciphered
            print("Encrypted message")

            decipherInitInfo = pb.DecryptInitRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, Parameter=iv),
                Key=generateKeyStatus.Key # you may want to store this
	    )
            decipherStateInit = cryptoClient.DecryptInit(decipherInitInfo)

            decipherDataUpdate = pb.DecryptUpdateRequest(
                State=decipherStateInit.State,
                Ciphered=ciphertext[:16]
	    )
            decipherStateUpdate = cryptoClient.DecryptUpdate(decipherDataUpdate)

            plaintext = decipherStateUpdate.Plain[:]
            decipherDataUpdate = pb.DecryptUpdateRequest(
	        State=decipherStateUpdate.State,
	        Ciphered=ciphertext[16:]
	    )
            decipherStateUpdate = cryptoClient.DecryptUpdate(decipherDataUpdate)

            plaintext = plaintext + decipherStateUpdate.Plain

            decipherDataFinal = pb.DecryptFinalRequest(
	        State=decipherStateUpdate.State
	    )
            decipherStateFinal = cryptoClient.DecryptFinal(decipherDataFinal)

            plaintext = plaintext + decipherStateFinal.Plain
            
            if plain != plaintext:
                print("Failed comparing plain text of cipher single")

            print("Decrypted message\n{}\n".format(plaintext))

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

	# Output:
	# Generated AES Key
	# Generated IV
	# Encrypted message
	# Decrypted message
	# Hello, this is a very long and creative message without any imagination

# Example_digest calculates the digest of some plain text
# Flow: connect, digest single-part data, digest multi-part data
def Example_digest():
    with util.Channel(credentials).get_channel(address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
            digestData = b'This is the data longer than 64 bytes This is the data longer than 64 bytes'
            digestInitRequest = pb.DigestInitRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_SHA256)
	    )
            digestInitResponse = cryptoClient.DigestInit(digestInitRequest)

            digestRequest = pb.DigestRequest(
		State=digestInitResponse.State,
		Data=digestData
            )
            digestResponse = cryptoClient.Digest(digestRequest)

            print("Digest data using a single digest operation: {}\n".format(digestResponse.Digest.hex()))

	    # Digest using mutiple operations
            digestInitResponse = cryptoClient.DigestInit(digestInitRequest)

            digestUpdateRequest = pb.DigestUpdateRequest(
                State=digestInitResponse.State,
                Data=digestData[:64]
            )
            digestUpdateResponse = cryptoClient.DigestUpdate(digestUpdateRequest)

            digestUpdateRequest = pb.DigestUpdateRequest(
                State=digestUpdateResponse.State,
                Data=digestData[64:]
            )
            digestUpdateResponse = cryptoClient.DigestUpdate(digestUpdateRequest)

            digestFinalRequestInfo = pb.DigestFinalRequest(
                State=digestUpdateResponse.State
            )
            digestFinalResponse = cryptoClient.DigestFinal(digestFinalRequestInfo)

            print("Digest data using multiple operations: {}\n".format(digestFinalResponse.Digest.hex()))

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

        # Output:
	# Digest data using a single digest operation: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
	# Digest data using multiple operations: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c

        
# Example_signAndVerifyUsingRSAKeyPair signs some data and verifies it
# Flow: connect, generate RSA key pair, sign single-part data, verify single-part data
def Example_signAndVerifyUsingRSAKeyPair():
    with util.Channel(credentials).get_channel(address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
	    # Generate RSA key pairs
            publicExponent = b'\x11'
            publicKeyTemplate=util.ep11attributes({
                ep11.CKA_ENCRYPT: True,
                ep11.CKA_VERIFY: True, # to verify a signature
                ep11.CKA_MODULUS_BITS: 2048,
                ep11.CKA_PUBLIC_EXPONENT: publicExponent,
                ep11.CKA_EXTRACTABLE: False
            })
            privateKeyTemplate=util.ep11attributes({
                ep11.CKA_PRIVATE: True,
                ep11.CKA_SENSITIVE: True,
                ep11.CKA_DECRYPT: True,
                ep11.CKA_SIGN: True, # to generate a signature
                ep11.CKA_EXTRACTABLE: False
            })
            generateKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_RSA_PKCS_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyTemplate,
		PrivKeyTemplate=privateKeyTemplate,
		#PrivKeyId=str(uuid.uuid4()),
		#PubKeyId=str(uuid.uuid4())
            )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateKeypairRequest)

            print("Generated RSA PKCS key pair")

	    # Sign data
            signInitRequest = pb.SignInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_SHA1_RSA_PKCS),
		PrivKey=generateKeyPairStatus.PrivKey
            )
            signInitResponse = cryptoClient.SignInit(signInitRequest)

            signData = hashlib.sha256(b'This data needs to be signed').digest()
            signRequest = pb.SignRequest(
		State=signInitResponse.State,
		Data=signData
            )
            SignResponse = cryptoClient.Sign(signRequest)

            print("Data signed")

            verifyInitRequest = pb.VerifyInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_SHA1_RSA_PKCS),
		PubKey=generateKeyPairStatus.PubKey
            )
            verifyInitResponse = cryptoClient.VerifyInit(verifyInitRequest)

            verifyRequest = pb.VerifyRequest(
                State=verifyInitResponse.State,
		Data=signData,
		Signature=SignResponse.Signature
            )
            cryptoClient.Verify(verifyRequest)
            print("Verified")

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

	# Output:
	#  Generated RSA PKCS key pair
	#  Data signed
	#  Verified

        
# Example_signAndVerifyUsingECDSAKeyPair generates an ECDSA key pair and uses the key pair to sign and verify data
# Flow: connect, generate ECDSA key pair, sign single-part data, verify single-part data
def Example_signAndVerifyUsingECDSAKeyPair():
    with util.Channel(credentials).get_channel(address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
            encoder = asn1.Encoder()
            encoder.start()
            encoder.write('1.2.840.10045.3.1.7', asn1.Numbers.ObjectIdentifier)
            ecParameters = encoder.output()
            
            if not ecParameters:
                raise Exception("Unable to encode parameter OID")

            publicKeyECTemplate = util.ep11attributes({
                ep11.CKA_EC_PARAMS: ecParameters,
                ep11.CKA_VERIFY: True,
                ep11.CKA_EXTRACTABLE: False
            })
            privateKeyECTemplate = util.ep11attributes({
                ep11.CKA_SIGN: True,
                ep11.CKA_EXTRACTABLE: False
            })
            generateECKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_EC_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyECTemplate,
		PrivKeyTemplate=privateKeyECTemplate
	    )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateECKeypairRequest)
            
            print("Generated ECDSA PKCS key pair")

	    # Sign data
            signInitRequest = pb.SignInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDSA),
		PrivKey=generateKeyPairStatus.PrivKey
            )
            signInitResponse = cryptoClient.SignInit(signInitRequest)

            signData = hashlib.sha256(b'This data needs to be signed').digest()
            signRequest = pb.SignRequest(
		State=signInitResponse.State,
		Data=signData
            )
            SignResponse = cryptoClient.Sign(signRequest)

            print("Data signed")

            verifyInitRequest = pb.VerifyInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDSA),
		PubKey=generateKeyPairStatus.PubKey
	    )
            verifyInitResponse = cryptoClient.VerifyInit(verifyInitRequest)

            verifyRequest = pb.VerifyRequest(
		State=verifyInitResponse.State,
		Data=signData,
		Signature=SignResponse.Signature
	    )
            cryptoClient.Verify(verifyRequest)
            print("Verified")

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

	# Output:
	# Generated ECDSA PKCS key pair
	# Data signed
	# Verified

# Example_signAndVerifyToTestErrorHandling signs some data, modifies the signature and verifies the expected returned error code
# Flow: connect, generate ECDSA key pair, sign single-part data, modify signature to force verify error,
#                verify single-part data, ensure proper error is returned
def Example_signAndVerifyToTestErrorHandling():
    with util.Channel(credentials).get_channel(address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            encoder = asn1.Encoder()
            encoder.start()
            encoder.write('1.2.840.10045.3.1.7', asn1.Numbers.ObjectIdentifier)
            ecParameters = encoder.output()
            
            if not ecParameters:
                raise Exception("Unable to encode parameter OID")

            publicKeyECTemplate = util.ep11attributes({
                ep11.CKA_EC_PARAMS: ecParameters,
                ep11.CKA_VERIFY: True,
                ep11.CKA_EXTRACTABLE: False
            })
            privateKeyECTemplate = util.ep11attributes({
                ep11.CKA_SIGN: True,
                ep11.CKA_EXTRACTABLE: False
            })
            generateECKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_EC_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyECTemplate,
		PrivKeyTemplate=privateKeyECTemplate
	    )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateECKeypairRequest)
            
            print("Generated ECDSA PKCS key pair")

	    # Sign data
            signInitRequest = pb.SignInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDSA),
		PrivKey=generateKeyPairStatus.PrivKey
	    )
            signInitResponse = cryptoClient.SignInit(signInitRequest)

            signData = hashlib.sha256(b'This data needs to be signed').digest()
            signRequest = pb.SignRequest(
		State=signInitResponse.State,
		Data=signData
            )
            SignResponse = cryptoClient.Sign(signRequest)

            print("Data signed")

            # Modify signature to force returned error code
            signature = SignResponse.Signature
            badsig = bytearray(signature)
            badsig[0] = 255
            badsig = bytes(badsig)
            signature = badsig

            verifyInitRequest = pb.VerifyInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDSA),
		PubKey=generateKeyPairStatus.PubKey
            )
            verifyInitResponse = cryptoClient.VerifyInit(verifyInitRequest)

            verifyRequest = pb.VerifyRequest(
                State=verifyInitResponse.State,
                Data=signData,
                Signature=signature
            )
            cryptoClient.Verify(verifyRequest)
            print("Verified")
            
        except grpc.RpcError as rpc_error:
            if rpc_error.details() == 'CKR_SIGNATURE_INVALID':
                print('Successfully detected an invalid signature.')
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)
            
	# Output:
	# Generated ECDSA PKCS key pair
	# Data signed
	# Invalid signature

# Example_wrapAndUnWrapKey wraps an AES key with a RSA public key and then unwraps it with the private key
# Flow: connect, generate AES key, generate RSA key pair, wrap/unwrap AES key with RSA key pair
def Example_wrapAndUnwrapKey():
    with util.Channel(credentials).get_channel(address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            # Generate a AES key
            destKeyTemplate = util.ep11attributes({
                ep11.CKA_VALUE_LEN: 16, # 128 bits
                ep11.CKA_ENCRYPT: True,
                ep11.CKA_DECRYPT: True,
                ep11.CKA_EXTRACTABLE: True # must be true to be wrapped
            })
            generateKeyRequest = pb.GenerateKeyRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_KEY_GEN),
		Template=destKeyTemplate,
		# KeyId=str(uuid.uuid4()) # optional
            )
            generateNewKeyStatus = cryptoClient.GenerateKey(generateKeyRequest)

            print("Generated AES key")

            # Generate RSA key pairs
            publicExponent = b'\x11'
            publicKeyTemplate = util.ep11attributes({
                ep11.CKA_ENCRYPT: True,
                ep11.CKA_WRAP: True, # to wrap a key
                ep11.CKA_MODULUS_BITS: 2048,
                ep11.CKA_PUBLIC_EXPONENT: publicExponent,
                ep11.CKA_EXTRACTABLE: False
            })
            privateKeyTemplate = util.ep11attributes({
                ep11.CKA_PRIVATE: True,
                ep11.CKA_SENSITIVE: True,
                ep11.CKA_DECRYPT: True,
                ep11.CKA_UNWRAP: True, # to unwrap a key
                ep11.CKA_EXTRACTABLE: False
            })
            generateKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_RSA_PKCS_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyTemplate,
		PrivKeyTemplate=privateKeyTemplate,
		# PrivKeyId=str(uuid.uuid4()),
		# PubKeyId=str(uuid.uuid4())
	    )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateKeypairRequest)

            print("Generated PKCS key pair")

            wrapKeyRequest = pb.WrapKeyRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_RSA_PKCS),
		KeK=generateKeyPairStatus.PubKey,
		Key=generateNewKeyStatus.Key
	    )
            wrapKeyResponse = cryptoClient.WrapKey(wrapKeyRequest)

            print("Wraped AES key")

            desUnwrapKeyTemplate = util.ep11attributes({
                ep11.CKA_CLASS: ep11.CKO_SECRET_KEY,
                ep11.CKA_KEY_TYPE: ep11.CKK_AES,
                ep11.CKA_VALUE_LEN: int(128/8),
                ep11.CKA_ENCRYPT: True,
                ep11.CKA_DECRYPT: True,
                ep11.CKA_EXTRACTABLE: True # must be true to be wrapped
            })
            unwrapRequest = pb.UnwrapKeyRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_RSA_PKCS),
		KeK=generateKeyPairStatus.PrivKey,
		Wrapped=wrapKeyResponse.Wrapped,
		Template=desUnwrapKeyTemplate
	    )
            unWrappedResponse = cryptoClient.UnwrapKey(unwrapRequest)

            if generateNewKeyStatus.CheckSum[:3] != unWrappedResponse.CheckSum[:3]:
                raise Exception("Unwrap AES key has a different checksum than the original key")
            else:
                print("Unwraped AES key")

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)
            
	# Output:
	# Generated AES key
	# Generated PKCS key pair
	# Wraped AES key
	# Unwraped AES key

# Example_deriveKey generates ECDHE key pairs for Bob and Alice and then generates AES keys for both of them.
# The names Alice and Bob are described in https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange.
# Flow: connect, generate key pairs, derive AES key for Bob, derive AES key for Alice, encrypt with Alice's AES key and decrypt with Bob's AES key
def Example_deriveKey():
    with util.Channel(credentials).get_channel(address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

	    # Generate ECDH key pairs for Alice and Bob
            encoder = asn1.Encoder()
            encoder.start()
            encoder.write('1.2.840.10045.3.1.7', asn1.Numbers.ObjectIdentifier)
            ecParameters = encoder.output()
            
            if not ecParameters:
                raise Exception("Unable to encode parameter OID")

            publicKeyECTemplate = util.ep11attributes({
                ep11.CKA_EC_PARAMS: ecParameters,
                ep11.CKA_EXTRACTABLE: False
            })
            privateKeyECTemplate = util.ep11attributes({
                ep11.CKA_DERIVE: True,
                ep11.CKA_EXTRACTABLE: False
            })
            generateECKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_EC_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyECTemplate,
		PrivKeyTemplate=privateKeyECTemplate
	    )
            aliceECKeypairResponse = cryptoClient.GenerateKeyPair(generateECKeypairRequest)

            print("Generated Alice EC key pair")

            bobECKeypairResponse = cryptoClient.GenerateKeyPair(generateECKeypairRequest)

            print("Generated Bob EC key pair")

	    # Derive AES key for Alice
            deriveKeyTemplate = util.ep11attributes({
                ep11.CKA_CLASS: ep11.CKO_SECRET_KEY,
                ep11.CKA_KEY_TYPE: ep11.CKK_AES,
                ep11.CKA_VALUE_LEN: int(128/8),
                ep11.CKA_ENCRYPT: True,
                ep11.CKA_DECRYPT: True,
            })
            combinedCoordinates = util.GetPubkeyBytesFromSPKI(bobECKeypairResponse.PubKey)
            if not combinedCoordinates:
                raise Exception("Bob's EC key cannot obtain coordinates")
            aliceDerivekeyRequest = pb.DeriveKeyRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDH1_DERIVE, Parameter=combinedCoordinates),
		Template=deriveKeyTemplate,
		BaseKey=aliceECKeypairResponse.PrivKey
            )
            aliceDerivekeyResponse = cryptoClient.DeriveKey(aliceDerivekeyRequest)

            # Derive AES key for Bob
            combinedCoordinates = util.GetPubkeyBytesFromSPKI(aliceECKeypairResponse.PubKey)
            if not combinedCoordinates:
                raise Exception("Alice's EC key cannot obtain coordinates")
            bobDerivekeyRequest = pb.DeriveKeyRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDH1_DERIVE, Parameter=combinedCoordinates),
		Template=deriveKeyTemplate,
		BaseKey=bobECKeypairResponse.PrivKey
            )
            bobDerivekeyResponse = cryptoClient.DeriveKey(bobDerivekeyRequest)

	    # Encrypt with Alice's key and decrypt with Bob's key
            msg = b'hello world!'
            rngTemplate = pb.GenerateRandomRequest(
		Len=int(ep11.AES_BLOCK_SIZE)
            )
            rng = cryptoClient.GenerateRandom(rngTemplate)

            iv = rng.Rnd[:ep11.AES_BLOCK_SIZE]

            encryptRequest = pb.EncryptSingleRequest(
                Key=aliceDerivekeyResponse.NewKey,
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, Parameter=iv),
		Plain=msg
            )
            encryptResponse = cryptoClient.EncryptSingle(encryptRequest)
            
            decryptRequest = pb.DecryptSingleRequest(
		Key=bobDerivekeyResponse.NewKey,
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, Parameter=iv),
		Ciphered=encryptResponse.Ciphered
            )
            decryptResponse = cryptoClient.DecryptSingle(decryptRequest)

            if decryptResponse.Plain != msg:
                raise Exception("Decrypted message{} is different from the original message: {}".format(decryptResponse.Plain, msg))
            else:
                print("Alice and Bob get the same derived key")

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

        # Output:
	# Generated Alice EC key pair
	# Generated Bob EC key pair
	# Alice and Bob get the same derived key
        
if __name__ == '__main__':
    Example_getMechanismInfo()
    Example_encryptAndDecrypt()
    Example_digest()
    Example_signAndVerifyUsingRSAKeyPair()
    Example_signAndVerifyUsingECDSAKeyPair()
    Example_signAndVerifyToTestErrorHandling()
    Example_wrapAndUnwrapKey()
    Example_deriveKey()
