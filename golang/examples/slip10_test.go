/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"crypto/tls"
    "crypto/x509"
    yaml "gopkg.in/yaml.v2"

    "google.golang.org/grpc/credentials"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	grpc "google.golang.org/grpc"
)

var yamlConfig, _ = ioutil.ReadFile("credential.yaml")

var     m = make(map[interface{}]interface{})
var err = yaml.Unmarshal([]byte(yamlConfig), &m)

var address = m["url"].(string)
var (
    crt = m["cert_path"].(string)
    key = m["key_path"].(string)
    ca  = m["cacert_path"].(string)
)

var certificate, _ = tls.LoadX509KeyPair(crt, key)
var certPool = x509.NewCertPool()
var cacert, _ = ioutil.ReadFile(ca)
var a = certPool.AppendCertsFromPEM(cacert)

var creds = credentials.NewTLS(&tls.Config{
    ServerName:   address, // NOTE: this is required!
    Certificates: []tls.Certificate{certificate},
    RootCAs:      certPool,
})

var callOpts = []grpc.DialOption{
        grpc.WithTransportCredentials(creds),
}

func Example_slip10DeriveKey() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	// SLIP10 has been verified for NIST P-256 and Secp256k1
	supportedCurves := []asn1.ObjectIdentifier{util.OIDNamedCurveP256, util.OIDNamedCurveSecp256k1, util.OIDNamedCurveED25519}
	for _, oid := range supportedCurves {
		fmt.Printf("Curve: %+v\n", oid)
		slip10_testCurve(cryptoClient, oid)
	}

	// Output:
	// Curve: 1.2.840.10045.3.1.7
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Curve: 1.3.132.0.10
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Curve: 1.3.101.112
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483649
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483649
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483650
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483650
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
}

func slip10_testCurve(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier) {

	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_KEY_TYPE:        ep11.CKK_GENERIC_SECRET,
				ep11.CKA_CLASS:           ep11.CKO_SECRET_KEY,
				ep11.CKA_VALUE_LEN:       (uint64)(256 / 8),
				ep11.CKA_WRAP:            false,
				ep11.CKA_UNWRAP:          false,
				ep11.CKA_SIGN:            true,
				ep11.CKA_VERIFY:          true,
				ep11.CKA_EXTRACTABLE:     false,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_IBM_USE_AS_DATA: true,
			},
		),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generated Generic Secret Key error: %+v %s", generateKeyRequest, err))
	} else {
		fmt.Println("Generated Generic Secret Key")
	}

	masterSecretKey, masterChainCode := slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		oid,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)

	const maxDepth = 3
	const maxChild = 3
	const hardened = 0x80000000 // For ed25519 only hardened key generation from Private parent key to private child key is supported.
	var privateKey [maxDepth][maxChild][]byte
	var privateChainCode [maxDepth][maxChild][]byte
	var publicKey [maxDepth][maxChild][]byte
	var publicChainCode [maxDepth][maxChild][]byte
	var child, depth uint64

	for child = 0; child < maxChild; child++ {
		privateKey[0][child], privateChainCode[0][child] = slip10_deriveKey(
			cryptoClient,
			pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
			oid,
			child+hardened,
			masterSecretKey,
			masterChainCode,
		)
		publicKey[0][child], publicChainCode[0][child] = slip10_deriveKey(
			cryptoClient,
			pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
			oid,
			child+hardened,
			masterSecretKey,
			masterChainCode,
		)
	}
	for depth = 1; depth < maxDepth; depth++ {
		for child = 0; child < maxChild; child++ {
			privateKey[depth][child], privateChainCode[depth][child] = slip10_deriveKey(
				cryptoClient,
				pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
				oid,
				child+hardened,
				privateKey[depth-1][child],
				privateChainCode[depth-1][child],
			)
			publicKey[depth][child], publicChainCode[depth][child] = slip10_deriveKey(
				cryptoClient,
				pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
				oid,
				child+hardened,
				privateKey[depth-1][child],
				privateChainCode[depth-1][child],
			)
			// PUB2PUB is not supported yet
			/*
				publicKey[depth][child], publicChainCode[depth][child] = slip10_deriveKey(
					cryptoClient,
					pb.BTCDeriveParm_CkSLIP0010PUB2PUB,
					oid,
					child,
					publicKey[depth-1][child],
					publicChainCode[depth-1][child],
				)
			*/
		}
	}
	for depth = 0; depth < maxDepth; depth++ {
		for child = 0; child < maxChild; child++ {
			slip10_signAndVerifySingle(cryptoClient, oid, privateKey[depth][child], publicKey[depth][child])
		}
	}
}

func slip10_deriveKey(cryptoClient pb.CryptoClient, deriveType pb.BTCDeriveParm_BTCDeriveType, oid asn1.ObjectIdentifier, childKeyIndex uint64, baseKey []byte, chainCode []byte) ([]byte, []byte) {

	ecParameters, err := asn1.Marshal(oid)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}

	deriveKeyRequest := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_BTC_DERIVE,
			Parameter: &pb.Mechanism_BTCDeriveParameter{
				BTCDeriveParameter: &pb.BTCDeriveParm{
					Type:          deriveType,
					ChildKeyIndex: childKeyIndex,
					ChainCode:     chainCode,
					Version:       1,
				},
			},
		},
		Template: util.AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_VERIFY:          true,
				ep11.CKA_EXTRACTABLE:     false,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
				ep11.CKA_VALUE_LEN:       (uint64)(0),
				ep11.CKA_IBM_USE_AS_DATA: true,
				ep11.CKA_EC_PARAMS:       ecParameters,
			},
		),
		BaseKey: baseKey,
	}
	deriveKeyResponse, err := cryptoClient.DeriveKey(context.Background(), deriveKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Derived Child Key request: %+v error: %s", deriveKeyRequest, err))
	} else {
		fmt.Printf("Derived Key type=%s index=%d\n",
			pb.BTCDeriveParm_BTCDeriveType_name[(int32)(deriveType)], childKeyIndex)
	}

	return deriveKeyResponse.NewKeyBytes, deriveKeyResponse.CheckSum
}

func slip10_signAndVerify(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {

	mech := GetSignMechanismFromOID(oid)

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}
	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	signResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	for {
		if err == nil {
			break
		}
		fmt.Printf("Failed Sign [%s]", err)
		signResponse, err = cryptoClient.Sign(context.Background(), signRequest)
	}
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Println("Data signed")

	// Modify signature to force returned error code
	//SignResponse.Signature[0] = 255

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: mech},
		PubKey: publicKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: signResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Printf("Invalid signature\n")
			return false
		}
		panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		return false
	}
	fmt.Println("Signature verified")
	return true
}

func slip10_signAndVerifySingle(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {

	mech := GetSignMechanismFromOID(oid)

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
		Data:    signData,
	}
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	} else {
		fmt.Println("Data signed")
	}

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: mech},
		PubKey:    publicKey,
		Data:      signData,
		Signature: signSingleResponse.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
		return false
	}
	fmt.Println("Signature verified")
	return true
}

func GetSignMechanismFromOID(oid asn1.ObjectIdentifier) ep11.Mechanism {
	switch {
	case oid.Equal(util.OIDNamedCurveED25519):
		return ep11.CKM_IBM_ED25519_SHA512
	case oid.Equal(util.OIDNamedCurveP256):
		return ep11.CKM_ECDSA
	case oid.Equal(util.OIDNamedCurveSecp256k1):
		return ep11.CKM_ECDSA
	}
	panic(fmt.Errorf("Unexpected OID: %+v", oid))
}

func Example_slip10_invalid_signAndVerify() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	// SLIP10 has been verified for NIST P-256 and Secp256k1
	//util.OIDNamedCurveP256, util.OIDNamedCurveSecp256k1, util.OIDNamedCurveED25519

	//generate random seed key
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_KEY_TYPE:        ep11.CKK_GENERIC_SECRET,
				ep11.CKA_CLASS:           ep11.CKO_SECRET_KEY,
				ep11.CKA_VALUE_LEN:       (uint64)(256 / 8),
				ep11.CKA_WRAP:            false,
				ep11.CKA_UNWRAP:          false,
				ep11.CKA_SIGN:            true,
				ep11.CKA_VERIFY:          true,
				ep11.CKA_EXTRACTABLE:     false,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_IBM_USE_AS_DATA: true,
			},
		),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generated Generic Secret Key error: %+v %s", generateKeyRequest, err))
	} else {
		fmt.Println("Generated Generic Secret Key")
	}

	const hardened = 0x80000000

	//keys of NIST P-256
	var publicKey_p256, privateKey_p256 []byte
	masterSecretKey_p256, masterChainCode_p256 := slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveP256,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKey_p256, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveP256,
		hardened,
		masterSecretKey_p256,
		masterChainCode_p256,
	)
	publicKey_p256, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveP256,
		hardened,
		masterSecretKey_p256,
		masterChainCode_p256,
	)

	//keys of Secp256k1
	var privateKey_256k1, publicKey_256k1 []byte
	masterSecretKey_256k1, masterChainCode_256k1 := slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveSecp256k1,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKey_256k1, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveSecp256k1,
		hardened,
		masterSecretKey_256k1,
		masterChainCode_256k1,
	)
	publicKey_256k1, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveSecp256k1,
		hardened,
		masterSecretKey_256k1,
		masterChainCode_256k1,
	)

	//keys of ED25519
	var privateKey_ed25519, publicKey_ed25519 []byte
	masterSecretKey_ed25519, masterChainCode_ed25519 := slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveED25519,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKey_ed25519, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveED25519,
		hardened,
		masterSecretKey_ed25519,
		masterChainCode_ed25519,
	)
	publicKey_ed25519, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveED25519,
		hardened,
		masterSecretKey_ed25519,
		masterChainCode_ed25519,
	)
	//invalid sign with incorrect curve - NIST P-256 curve
	slip10_signAndVerify_crossErr(cryptoClient, util.OIDNamedCurveED25519, privateKey_p256, publicKey_p256)
	//nvalid sign with incorrect curve - secp256k1 curve
	slip10_signAndVerify_crossErr(cryptoClient, util.OIDNamedCurveED25519, privateKey_256k1, publicKey_256k1)
	//invalid sign with incorrect curve- ED25519 curve
	slip10_signAndVerify_crossErr(cryptoClient, util.OIDNamedCurveP256, privateKey_ed25519, publicKey_ed25519)
	//invalid verification
	slip10_signAndVerify_crossErr(cryptoClient, util.OIDNamedCurveP256, privateKey_p256, publicKey_256k1)
	slip10_signAndVerify_crossErr(cryptoClient, util.OIDNamedCurveSecp256k1, privateKey_256k1, publicKey_p256)
	slip10_signAndVerify_crossErr(cryptoClient, util.OIDNamedCurveED25519, privateKey_ed25519, publicKey_p256)

	// Output:
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// SignInit error with invalid Mechanism - 1.3.101.112
	// SignInit error with invalid Mechanism - 1.3.101.112
	// SignInit error with invalid Mechanism - 1.2.840.10045.3.1.7
	// Data signed
	// Invalid signature
	// Data signed
	// Invalid signature
	// Data signed
	// VerifyInit error with invalid Mechanism - 1.3.101.112
}

func slip10_signAndVerify_crossErr(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {

	mech := GetSignMechanismFromOID(oid)

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		fmt.Printf("SignInit error with invalid Mechanism - %s\n", oid)
		return false
	}

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	signResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	for {
		if err == nil {
			break
		}
		fmt.Printf("Failed Sign [%s]", err)
		signResponse, err = cryptoClient.Sign(context.Background(), signRequest)
	}
	if err != nil {
		fmt.Printf("Sign error with invalid Mechanism - %s\n", oid)
	}
	fmt.Println("Data signed")

	// Modify signature to force returned error code
	//SignResponse.Signature[0] = 255

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: mech},
		PubKey: publicKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		fmt.Printf("VerifyInit error with invalid Mechanism - %s\n", oid)
		return false
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: signResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Printf("Invalid signature\n")
			return false
		}
		fmt.Printf("Signature error with invalid Mechanism - %s\n", oid)
	}
	fmt.Println("Signature verified")
	return true
}

func Example_slip10_cross_signAndVerify() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	// SLIP10 has been verified for NIST P-256 and Secp256k1
	//util.OIDNamedCurveP256, util.OIDNamedCurveSecp256k1, util.OIDNamedCurveED25519

	//generate random seed key
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_GENERIC_SECRET_KEY_GEN},
		Template: util.AttributeMap(
			ep11.EP11Attributes{
				ep11.CKA_KEY_TYPE:        ep11.CKK_GENERIC_SECRET,
				ep11.CKA_CLASS:           ep11.CKO_SECRET_KEY,
				ep11.CKA_VALUE_LEN:       (uint64)(256 / 8),
				ep11.CKA_WRAP:            false,
				ep11.CKA_UNWRAP:          false,
				ep11.CKA_SIGN:            true,
				ep11.CKA_VERIFY:          true,
				ep11.CKA_EXTRACTABLE:     false,
				ep11.CKA_DERIVE:          true,
				ep11.CKA_IBM_USE_AS_DATA: true,
			},
		),
	}
	generateKeyResponse, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generated Generic Secret Key error: %+v %s", generateKeyRequest, err))
	} else {
		fmt.Println("Generated Generic Secret Key")
	}

	const hardened = 0x80000000

	//keys of NIST P-256
	var publicKey_p256, privateKey_p256 []byte
	masterSecretKey_p256, masterChainCode_p256 := slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveP256,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKey_p256, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveP256,
		hardened,
		masterSecretKey_p256,
		masterChainCode_p256,
	)
	publicKey_p256, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveP256,
		hardened,
		masterSecretKey_p256,
		masterChainCode_p256,
	)

	//keys of Secp256k1
	var privateKey_256k1, publicKey_256k1 []byte
	masterSecretKey_256k1, masterChainCode_256k1 := slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveSecp256k1,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKey_256k1, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveSecp256k1,
		hardened,
		masterSecretKey_256k1,
		masterChainCode_256k1,
	)
	publicKey_256k1, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveSecp256k1,
		hardened,
		masterSecretKey_256k1,
		masterChainCode_256k1,
	)

	//keys of ED25519
	var privateKey_ed25519, publicKey_ed25519 []byte
	masterSecretKey_ed25519, masterChainCode_ed25519 := slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010MASTERK,
		util.OIDNamedCurveED25519,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	privateKey_ed25519, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PRV,
		util.OIDNamedCurveED25519,
		hardened,
		masterSecretKey_ed25519,
		masterChainCode_ed25519,
	)
	publicKey_ed25519, _ = slip10_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkSLIP0010PRV2PUB,
		util.OIDNamedCurveED25519,
		hardened,
		masterSecretKey_ed25519,
		masterChainCode_ed25519,
	)

	//signSingle, and verifyInit/verify
	slip10_signSingleAndVerify(cryptoClient, util.OIDNamedCurveP256, privateKey_p256, publicKey_p256)
	slip10_signSingleAndVerify(cryptoClient, util.OIDNamedCurveSecp256k1, privateKey_256k1, publicKey_256k1)
	slip10_signSingleAndVerify(cryptoClient, util.OIDNamedCurveED25519, privateKey_ed25519, publicKey_ed25519)
	//signInit/sign, verifySingle
	slip10_signAndVerifyInitAndSingle(cryptoClient, util.OIDNamedCurveP256, privateKey_p256, publicKey_p256)
	slip10_signAndVerifyInitAndSingle(cryptoClient, util.OIDNamedCurveSecp256k1, privateKey_256k1, publicKey_256k1)
	slip10_signAndVerifyInitAndSingle(cryptoClient, util.OIDNamedCurveED25519, privateKey_ed25519, publicKey_ed25519)

	// Output:
	// Generated Generic Secret Key
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Derived Key type=CkSLIP0010MASTERK index=0
	// Derived Key type=CkSLIP0010PRV2PRV index=2147483648
	// Derived Key type=CkSLIP0010PRV2PUB index=2147483648
	// Data signed - 1.2.840.10045.3.1.7
	// Signature verified - 1.2.840.10045.3.1.7
	// Data signed - 1.3.132.0.10
	// Signature verified - 1.3.132.0.10
	// Data signed - 1.3.101.112
	// Signature verified - 1.3.101.112
	// Data signed - 1.2.840.10045.3.1.7
	// Signature verified - 1.2.840.10045.3.1.7
	// Data signed - 1.3.132.0.10
	// Signature verified - 1.3.132.0.10
	// Data signed - 1.3.101.112
	// Signature verified - 1.3.101.112
}

func slip10_signSingleAndVerify(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {

	mech := GetSignMechanismFromOID(oid)

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
		Data:    signData,
	}
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}
	fmt.Printf("Data signed - %s\n", oid)

	// Modify signature to force returned error code
	//SignResponse.Signature[0] = 255

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: mech},
		PubKey: publicKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: signSingleResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Printf("Invalid signature\n")
			return false
		}
		panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		return false
	}
	fmt.Printf("Signature verified - %s\n", oid)
	return true
}

func slip10_signAndVerifyInitAndSingle(cryptoClient pb.CryptoClient, oid asn1.ObjectIdentifier, privateKey []byte, publicKey []byte) bool {

	mech := GetSignMechanismFromOID(oid)

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: mech},
		PrivKey: privateKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit error: %s", err))
	}
	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	signResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	for {
		if err == nil {
			break
		}
		fmt.Printf("Failed Sign [%s]", err)
		signResponse, err = cryptoClient.Sign(context.Background(), signRequest)
	}
	if err != nil {
		panic(fmt.Errorf("Sign error: %s", err))
	}
	fmt.Printf("Data signed - %s\n", oid)

	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: mech},
		PubKey:    publicKey,
		Data:      signData,
		Signature: signResponse.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid signature"))
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
		return false
	}
	fmt.Printf("Signature verified - %s\n", oid)
	return true
}
