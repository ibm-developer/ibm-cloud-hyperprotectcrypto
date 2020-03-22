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
    
            if not mechanismListResponse:
                raise Exception("Get mechanism list error")

            print("Got mechanism list:\n{} ...\n".format(mechanismListResponse.Mechs[:1]))

            mechanismInfoRequest = pb.GetMechanismInfoRequest(Mech=ep11.CKM_RSA_PKCS)
            mechanismInfoResponse = cryptoClient.GetMechanismInfo(mechanismInfoRequest)

            if not mechanismInfoResponse:
                raise Exception("Get mechanism info error")
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
            template={}
            template[ep11.CKA_VALUE_LEN] = int(keyLen/8).to_bytes(8,byteorder='big')
            template[ep11.CKA_WRAP] = int(False).to_bytes(1,byteorder='big')
            template[ep11.CKA_UNWRAP] = int(False).to_bytes(1,byteorder='big')
            template[ep11.CKA_ENCRYPT] = int(True).to_bytes(1,byteorder='big')
            template[ep11.CKA_DECRYPT] = int(True).to_bytes(1,byteorder='big')
            template[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big') # set to false!
            template[ep11.CKA_TOKEN] = int(False).to_bytes(1,byteorder='big') # ignored by EP11

            r = pb.GenerateKeyRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_KEY_GEN),
                Template=template,
                # KeyId=str(uuid.uuid4()) # optional
            )

            generateKeyStatus = cryptoClient.GenerateKey(r)
            if not generateKeyStatus:
                raise Exception("GenerateKey Error")
            print("Generated AES Key")

            rngTemplate = pb.GenerateRandomRequest(
	        Len=(ep11.AES_BLOCK_SIZE)
	    )
        
            rng = cryptoClient.GenerateRandom(rngTemplate)
            if not rng:
                raise Exception("GenerateRandom Error")
            iv = rng.Rnd[:ep11.AES_BLOCK_SIZE]
            print("Generated IV")

            encipherInitInfo = pb.EncryptInitRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, Parameter=iv),
	        Key=generateKeyStatus.Key # you may want to store this
	    )
            cipherStateInit = cryptoClient.EncryptInit(encipherInitInfo)
            if not cipherStateInit:
                raise Exception("Failed EncryptInit")

            plain = b'Hello, this is a very long and creative message without any imagination'

            encipherDataUpdate = pb.EncryptUpdateRequest(
                State=cipherStateInit.State,
                Plain=plain[:20]
            )
            encipherStateUpdate = cryptoClient.EncryptUpdate(encipherDataUpdate)
            if not encipherStateUpdate:
                raise Exception("Failed Encrypt")

            ciphertext = encipherStateUpdate.Ciphered
            encipherDataUpdate = pb.EncryptUpdateRequest(
                State=encipherStateUpdate.State,
                Plain=plain[20:]
            )
            encipherStateUpdate = cryptoClient.EncryptUpdate(encipherDataUpdate)
            if not encipherStateUpdate:
                raise Exception("Failed Encrypt")

            ciphertext = ciphertext + encipherStateUpdate.Ciphered
            encipherDataFinal = pb.EncryptFinalRequest(
                State=encipherStateUpdate.State
            )
            encipherStateFinal = cryptoClient.EncryptFinal(encipherDataFinal)
            if not encipherStateFinal:
                raise Exception("Failed EncryptFinal")

            ciphertext = ciphertext + encipherStateFinal.Ciphered
            print("Encrypted message")

            decipherInitInfo = pb.DecryptInitRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, Parameter=iv),
                Key=generateKeyStatus.Key # you may want to store this
	    )
            decipherStateInit = cryptoClient.DecryptInit(decipherInitInfo)
            if not decipherStateInit:
                raise Exception("Failed DecryptInit")

            decipherDataUpdate = pb.DecryptUpdateRequest(
                State=decipherStateInit.State,
                Ciphered=ciphertext[:16]
	    )
            decipherStateUpdate = cryptoClient.DecryptUpdate(decipherDataUpdate)
            if not decipherStateUpdate:
                raise Exception("Failed DecryptUpdate")

            plaintext = decipherStateUpdate.Plain[:]
            decipherDataUpdate = pb.DecryptUpdateRequest(
	        State=decipherStateUpdate.State,
	        Ciphered=ciphertext[16:]
	    )
            decipherStateUpdate = cryptoClient.DecryptUpdate(decipherDataUpdate)
            if not decipherStateUpdate:
                raise Exception("Failed DecryptUpdate")
            plaintext = plaintext + decipherStateUpdate.Plain

            decipherDataFinal = pb.DecryptFinalRequest(
	        State=decipherStateUpdate.State
	    )
            decipherStateFinal = cryptoClient.DecryptFinal(decipherDataFinal)
            if not decipherStateFinal:
                raise Exception("Failed DecryptFinal")
            plaintext = plaintext + decipherStateFinal.Plain
            
            if plain != plaintext:
                print("Failed comparing plain text of cipher single")

            print("Decrypted message\n{}\n".format(plaintext))

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
            if not digestInitResponse:
                raise Exception("Digest init error")
            digestRequest = pb.DigestRequest(
		State=digestInitResponse.State,
		Data=digestData
            )
            digestResponse = cryptoClient.Digest(digestRequest)
            if not digestResponse:
                raise Exception("Digest error")
            else:
                print("Digest data using a single digest operation: {}\n".format(digestResponse.Digest.hex()))

	    # Digest using mutiple operations
            digestInitResponse = cryptoClient.DigestInit(digestInitRequest)
            if not digestInitResponse:
                raise Exception("Digest init error")
            digestUpdateRequest = pb.DigestUpdateRequest(
                State=digestInitResponse.State,
                Data=digestData[:64]
            )
            digestUpdateResponse = cryptoClient.DigestUpdate(digestUpdateRequest)
            if not digestUpdateResponse:
                raise Exception("Digest update error")
            digestUpdateRequest = pb.DigestUpdateRequest(
                State=digestUpdateResponse.State,
                Data=digestData[64:]
            )
            digestUpdateResponse = cryptoClient.DigestUpdate(digestUpdateRequest)
            if not digestUpdateResponse:
                raise Exception("Digest update error")
            digestFinalRequestInfo = pb.DigestFinalRequest(
                State=digestUpdateResponse.State
            )
            digestFinalResponse = cryptoClient.DigestFinal(digestFinalRequestInfo)
            if not digestFinalResponse:
                raise Exception("Digest final error")
            else:
                print("Digest data using multiple operations: {}\n".format(digestFinalResponse.Digest.hex()))

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
        
            digestData = b'This is the data longer than 64 bytes This is the data longer than 64 bytes'
            digestInitRequest = pb.DigestInitRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_SHA256)
	    )
            digestInitResponse = cryptoClient.DigestInit(digestInitRequest)

	    # Generate RSA key pairs
            publicExponent = b'\x11'
            publicKeyTemplate={}
            publicKeyTemplate[ep11.CKA_ENCRYPT] = int(True).to_bytes(1,byteorder='big')
            publicKeyTemplate[ep11.CKA_VERIFY] = int(True).to_bytes(1,byteorder='big') # to verify a signature
            publicKeyTemplate[ep11.CKA_MODULUS_BITS] = int(2048).to_bytes(8,byteorder='big')
            publicKeyTemplate[ep11.CKA_PUBLIC_EXPONENT] = publicExponent
            publicKeyTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')

            privateKeyTemplate={}
            privateKeyTemplate[ep11.CKA_PRIVATE] = int(True).to_bytes(1,byteorder='big')
            privateKeyTemplate[ep11.CKA_SENSITIVE] = int(True).to_bytes(1,byteorder='big')
            privateKeyTemplate[ep11.CKA_DECRYPT] = int(True).to_bytes(1,byteorder='big')
            privateKeyTemplate[ep11.CKA_SIGN] = int(True).to_bytes(1,byteorder='big') # to generate a signature
            privateKeyTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')

            generateKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_RSA_PKCS_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyTemplate,
		PrivKeyTemplate=privateKeyTemplate,
		#PrivKeyId=str(uuid.uuid4()),
		#PubKeyId=str(uuid.uuid4())
            )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateKeypairRequest)
            if not generateKeyPairStatus:
                raise Exception("GenerateKeyPair error")
            print("Generated RSA PKCS key pair")

	    # Sign data
            signInitRequest = pb.SignInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_SHA1_RSA_PKCS),
		PrivKey=generateKeyPairStatus.PrivKey
            )
            signInitResponse = cryptoClient.SignInit(signInitRequest)
            if not signInitResponse:
                raise Exception("SignInit error")

            signData = hashlib.sha256(b'This data needs to be signed').digest()
            signRequest = pb.SignRequest(
		State=signInitResponse.State,
		Data=signData
            )
            SignResponse = cryptoClient.Sign(signRequest)
            if not SignResponse:
                raise Exception("Sign error")
            print("Data signed")

            verifyInitRequest = pb.VerifyInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_SHA1_RSA_PKCS),
		PubKey=generateKeyPairStatus.PubKey
            )
            verifyInitResponse = cryptoClient.VerifyInit(verifyInitRequest)
            if not verifyInitResponse:
                raise Exception("VerifyInit error")
            verifyRequest = pb.VerifyRequest(
                State=verifyInitResponse.State,
		Data=signData,
		Signature=SignResponse.Signature
            )
            cryptoClient.Verify(verifyRequest)
            print("Verified")

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

            publicKeyECTemplate = {}
            publicKeyECTemplate[ep11.CKA_EC_PARAMS] = ecParameters
            publicKeyECTemplate[ep11.CKA_VERIFY] = int(True).to_bytes(1,byteorder='big')
            publicKeyECTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')

            privateKeyECTemplate = {}
            privateKeyECTemplate[ep11.CKA_SIGN] = int(True).to_bytes(1,byteorder='big')
            privateKeyECTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')

            generateECKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_EC_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyECTemplate,
		PrivKeyTemplate=privateKeyECTemplate
	    )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateECKeypairRequest)
            if not generateKeyPairStatus:
                raise Exception("GenerateKeyPair error")
            
            print("Generated ECDSA PKCS key pair")

	    # Sign data
            signInitRequest = pb.SignInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDSA),
		PrivKey=generateKeyPairStatus.PrivKey
            )
            signInitResponse = cryptoClient.SignInit(signInitRequest)
            if not signInitResponse:
                raise Exception("SignInit error")
            signData = hashlib.sha256(b'This data needs to be signed').digest()
            signRequest = pb.SignRequest(
		State=signInitResponse.State,
		Data=signData
            )
            SignResponse = cryptoClient.Sign(signRequest)
            if not SignResponse:
                raise Exception("Sign error")
            print("Data signed")

            verifyInitRequest = pb.VerifyInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDSA),
		PubKey=generateKeyPairStatus.PubKey
	    )
            verifyInitResponse = cryptoClient.VerifyInit(verifyInitRequest)
            if not verifyInitResponse:
                raise Exception("VerifyInit error")
            verifyRequest = pb.VerifyRequest(
		State=verifyInitResponse.State,
		Data=signData,
		Signature=SignResponse.Signature
	    )
            cryptoClient.Verify(verifyRequest)
            print("Verified")

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

            publicKeyECTemplate = {}
            publicKeyECTemplate[ep11.CKA_EC_PARAMS] = ecParameters
            publicKeyECTemplate[ep11.CKA_VERIFY] = int(True).to_bytes(1,byteorder='big')
            publicKeyECTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')
            
            privateKeyECTemplate = {}
            privateKeyECTemplate[ep11.CKA_SIGN] = int(True).to_bytes(1,byteorder='big')
            privateKeyECTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')

            generateECKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_EC_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyECTemplate,
		PrivKeyTemplate=privateKeyECTemplate
	    )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateECKeypairRequest)
            if not generateKeyPairStatus:
                raise Exception("GenerateKeyPair error")
            
            print("Generated ECDSA PKCS key pair")
            generateECKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_EC_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyECTemplate,
		PrivKeyTemplate=privateKeyECTemplate
	    )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateECKeypairRequest)
            if not generateKeyPairStatus:
                raise Exception("GenerateKeyPair error")
            
            print("Generated ECDSA PKCS key pair")

	    # Sign data
            signInitRequest = pb.SignInitRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDSA),
		PrivKey=generateKeyPairStatus.PrivKey
	    )
            signInitResponse = cryptoClient.SignInit(signInitRequest)
            if not signInitResponse:
                raise Exception("SignInit error")
            signData = hashlib.sha256(b'This data needs to be signed').digest()
            signRequest = pb.SignRequest(
		State=signInitResponse.State,
		Data=signData
            )
            SignResponse = cryptoClient.Sign(signRequest)
            if not SignResponse:
                raise Exception("Sign error")
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
            if not verifyInitResponse:
                raise Exception("VerifyInit error")
            verifyRequest = pb.VerifyRequest(
                State=verifyInitResponse.State,
                Data=signData,
                Signature=signature
            )
            cryptoClient.Verify(verifyRequest)
            print("Verified")
            
        except grpc.RpcError as rpc_error:
            if rpc_error.details() == 'CKR_SIGNATURE_INVALID':
                print('Successfully catch an invalid signature.')
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
            destKeyTemplate = {}
            destKeyTemplate[ep11.CKA_VALUE_LEN] = int(128/8).to_bytes(8,byteorder='big')
            destKeyTemplate[ep11.CKA_ENCRYPT] = int(True).to_bytes(1,byteorder='big')
            destKeyTemplate[ep11.CKA_DECRYPT] = int(True).to_bytes(1,byteorder='big')
            destKeyTemplate[ep11.CKA_EXTRACTABLE] = int(True).to_bytes(1,byteorder='big') # must be true to be wrapped

            generateKeyRequest = pb.GenerateKeyRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_KEY_GEN),
		Template=destKeyTemplate,
		# KeyId=str(uuid.uuid4()) # optional
            )
            generateNewKeyStatus = cryptoClient.GenerateKey(generateKeyRequest)
            if not generateNewKeyStatus:
                raise Exception("Generate AES key error")
            else:
                print("Generated AES key")

            # Generate RSA key pairs
            publicExponent = b'\x11'
            publicKeyTemplate = {}
            publicKeyTemplate[ep11.CKA_ENCRYPT] = int(True).to_bytes(1,byteorder='big')
            publicKeyTemplate[ep11.CKA_WRAP] = int(True).to_bytes(1,byteorder='big') # to wrap a key
            publicKeyTemplate[ep11.CKA_MODULUS_BITS] = int(2048).to_bytes(8,byteorder='big')
            publicKeyTemplate[ep11.CKA_PUBLIC_EXPONENT] = publicExponent
            publicKeyTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')
            
            privateKeyTemplate = {}
            privateKeyTemplate[ep11.CKA_PRIVATE] = int(True).to_bytes(1,byteorder='big')
            privateKeyTemplate[ep11.CKA_SENSITIVE] = int(True).to_bytes(1,byteorder='big')
            privateKeyTemplate[ep11.CKA_DECRYPT] = int(True).to_bytes(1,byteorder='big')
            privateKeyTemplate[ep11.CKA_UNWRAP] = int(True).to_bytes(1,byteorder='big') # to unwrap a key
            privateKeyTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')
            generateKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_RSA_PKCS_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyTemplate,
		PrivKeyTemplate=privateKeyTemplate,
		# PrivKeyId=str(uuid.uuid4()),
		# PubKeyId=str(uuid.uuid4())
	    )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateKeypairRequest)
            if not generateKeyPairStatus:
                raise Exception("GenerateKeyPair error")
            print("Generated PKCS key pair")

            wrapKeyRequest = pb.WrapKeyRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_RSA_PKCS),
		KeK=generateKeyPairStatus.PubKey,
		Key=generateNewKeyStatus.Key
	    )
            wrapKeyResponse = cryptoClient.WrapKey(wrapKeyRequest)
            if not wrapKeyResponse:
                raise Exception("Wrap AES key error")
            print("Wraped AES key")

            desUnwrapKeyTemplate = {}
            desUnwrapKeyTemplate[ep11.CKA_CLASS] = ep11.CKO_SECRET_KEY.to_bytes(8,byteorder='big')
            desUnwrapKeyTemplate[ep11.CKA_KEY_TYPE] = ep11.CKK_AES.to_bytes(8,byteorder='big')
            desUnwrapKeyTemplate[ep11.CKA_VALUE_LEN] = int(128/8).to_bytes(8,byteorder='big')
            desUnwrapKeyTemplate[ep11.CKA_ENCRYPT] = int(True).to_bytes(1,byteorder='big')
            desUnwrapKeyTemplate[ep11.CKA_DECRYPT] = int(True).to_bytes(1,byteorder='big')
            desUnwrapKeyTemplate[ep11.CKA_EXTRACTABLE] = int(True).to_bytes(1,byteorder='big') # must be true to be wrapped
            unwrapRequest = pb.UnwrapKeyRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_RSA_PKCS),
		KeK=generateKeyPairStatus.PrivKey,
		Wrapped=wrapKeyResponse.Wrapped,
		Template=desUnwrapKeyTemplate
	    )
            unWrappedResponse = cryptoClient.UnwrapKey(unwrapRequest)
            if  not unWrappedResponse:
                raise Exception("Unwrap AES key error")
            if generateNewKeyStatus.CheckSum[:3] != unWrappedResponse.CheckSum[:3]:
                raise Exception("Unwrap AES key has a different checksum than the original key")
            else:
                print("Unwraped AES key")

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

            publicKeyECTemplate = {}
            publicKeyECTemplate[ep11.CKA_EC_PARAMS] = ecParameters
            publicKeyECTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')

            privateKeyECTemplate = {}
            privateKeyECTemplate[ep11.CKA_DERIVE] = int(True).to_bytes(1,byteorder='big')
            privateKeyECTemplate[ep11.CKA_EXTRACTABLE] = int(False).to_bytes(1,byteorder='big')

            generateECKeypairRequest = pb.GenerateKeyPairRequest(
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_EC_KEY_PAIR_GEN),
		PubKeyTemplate=publicKeyECTemplate,
		PrivKeyTemplate=privateKeyECTemplate
	    )
            aliceECKeypairResponse = cryptoClient.GenerateKeyPair(generateECKeypairRequest)
            if not aliceECKeypairResponse:
                raise Exception("Generate Alice EC key pair error")
            print("Generated Alice EC key pair")

            bobECKeypairResponse = cryptoClient.GenerateKeyPair(generateECKeypairRequest)
            if not bobECKeypairResponse:
                raise Exception("Generate Bob EC key pair error")
            print("Generated Bob EC key pair")

	    # Derive AES key for Alice
            deriveKeyTemplate = {}
            deriveKeyTemplate[ep11.CKA_CLASS] = int(ep11.CKO_SECRET_KEY).to_bytes(8,byteorder='big')
            deriveKeyTemplate[ep11.CKA_KEY_TYPE] = int(ep11.CKK_AES).to_bytes(8,byteorder='big')
            deriveKeyTemplate[ep11.CKA_VALUE_LEN] = int(128/8).to_bytes(8,byteorder='big')
            deriveKeyTemplate[ep11.CKA_ENCRYPT] = int(True).to_bytes(1,byteorder='big')
            deriveKeyTemplate[ep11.CKA_DECRYPT] = int(True).to_bytes(1,byteorder='big')
            combinedCoordinates = util.GetPubkeyBytesFromSPKI(bobECKeypairResponse.PubKey)
            if not combinedCoordinates:
                raise Exception("Bob's EC key cannot obtain coordinates")
            aliceDerivekeyRequest = pb.DeriveKeyRequest(
                Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_ECDH1_DERIVE, Parameter=combinedCoordinates),
		Template=deriveKeyTemplate,
		BaseKey=aliceECKeypairResponse.PrivKey
            )
            aliceDerivekeyResponse = cryptoClient.DeriveKey(aliceDerivekeyRequest)
            if not aliceDerivekeyResponse:
                raise Exception("Alice EC key derive error")

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
            if not bobDerivekeyResponse:
                raise Exception("Bob EC Key Derive Error")

	    # Encrypt with Alice's key and decrypt with Bob's key
            msg = b'hello world!'
            rngTemplate = pb.GenerateRandomRequest(
		Len=int(ep11.AES_BLOCK_SIZE)
            )
            rng = cryptoClient.GenerateRandom(rngTemplate)
            if not rng:
                raise Exception("GenerateRandom error")
            iv = rng.Rnd[:ep11.AES_BLOCK_SIZE]
            encryptRequest = pb.EncryptSingleRequest(
                Key=aliceDerivekeyResponse.NewKey,
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, Parameter=iv),
		Plain=msg
            )
            encryptResponse = cryptoClient.EncryptSingle(encryptRequest)
            if not encryptResponse:
                raise Exception("Encrypt error")
            
            decryptRequest = pb.DecryptSingleRequest(
		Key=bobDerivekeyResponse.NewKey,
		Mech=pkcs11_pb2.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, Parameter=iv),
		Ciphered=encryptResponse.Ciphered
            )
            decryptResponse = cryptoClient.DecryptSingle(decryptRequest)
            if not decryptResponse:
                raise Exception("Decrypt error")

            if decryptResponse.Plain != msg:
                raise Exception("Decrypted message{} is different from the original message: {}".format(decryptResponse.Plain, msg))
            else:
                print("Alice and Bob get the same derived key")

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