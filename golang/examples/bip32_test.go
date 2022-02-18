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
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
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

func Example_bip32DeriveKey() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

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
	masterSecretKey, masterChainCode := bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032MASTERK,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)

	const maxDepth = 3
	const maxChild = 3
	var privateKey [maxDepth][maxChild][]byte
	var privateChainCode [maxDepth][maxChild][]byte
	var publicKey [maxDepth][maxChild][]byte
	var publicChainCode [maxDepth][maxChild][]byte
	var child, depth uint64

	for child = 0; child < maxChild; child++ {
		privateKey[0][child], privateChainCode[0][child] = bip32_deriveKey(
			cryptoClient,
			pb.BTCDeriveParm_CkBIP0032PRV2PRV,
			child,
			masterSecretKey,
			masterChainCode,
		)
		publicKey[0][child], publicChainCode[0][child] = bip32_deriveKey(
			cryptoClient,
			pb.BTCDeriveParm_CkBIP0032PRV2PUB,
			child,
			masterSecretKey,
			masterChainCode,
		)
	}
	for depth = 1; depth < maxDepth; depth++ {
		for child = 0; child < maxChild; child++ {
			privateKey[depth][child], privateChainCode[depth][child] = bip32_deriveKey(
				cryptoClient,
				pb.BTCDeriveParm_CkBIP0032PRV2PRV,
				child,
				privateKey[depth-1][child],
				privateChainCode[depth-1][child],
			)
			publicKey[depth][child], publicChainCode[depth][child] = bip32_deriveKey(
				cryptoClient,
				pb.BTCDeriveParm_CkBIP0032PRV2PUB,
				child,
				privateKey[depth-1][child],
				privateChainCode[depth-1][child],
			)
			// PUB2PUB is not supported yet
			/*
			   publicKey[depth][child], publicChainCode[depth][child] = bip32_deriveKey(
			       cryptoClient,
			       pb.BTCDeriveParm_CkBIP0032PUB2PUB,
			       child,
			       publicKey[depth-1][child],
			       publicChainCode[depth-1][child],
			   )
			*/
		}
	}
	for depth = 0; depth < maxDepth; depth++ {
		for child = 0; child < maxChild; child++ {
			bip32_signAndVerifySingle(cryptoClient, privateKey[depth][child], publicKey[depth][child])
		}
	}

	// Output:
	// Generated Generic Secret Key
	// Derived Key type=CkBIP0032MASTERK index=0
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Derived Key type=CkBIP0032PRV2PRV index=1
	// Derived Key type=CkBIP0032PRV2PUB index=1
	// Derived Key type=CkBIP0032PRV2PRV index=2
	// Derived Key type=CkBIP0032PRV2PUB index=2
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Derived Key type=CkBIP0032PRV2PRV index=1
	// Derived Key type=CkBIP0032PRV2PUB index=1
	// Derived Key type=CkBIP0032PRV2PRV index=2
	// Derived Key type=CkBIP0032PRV2PUB index=2
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Derived Key type=CkBIP0032PRV2PRV index=1
	// Derived Key type=CkBIP0032PRV2PUB index=1
	// Derived Key type=CkBIP0032PRV2PRV index=2
	// Derived Key type=CkBIP0032PRV2PUB index=2
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

func bip32_deriveKey(cryptoClient pb.CryptoClient, deriveType pb.BTCDeriveParm_BTCDeriveType, childKeyIndex uint64, baseKey []byte, chainCode []byte) ([]byte, []byte) {

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveSecp256k1)
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

func bip32_signAndVerify(cryptoClient pb.CryptoClient, privateKey []byte, publicKey []byte) bool {

	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
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
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
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

func bip32_signAndVerifySingle(cryptoClient pb.CryptoClient, privateKey []byte, publicKey []byte) bool {

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
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
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
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

//general tests cases
func Example_bip32_Base() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	fmt.Printf("Generating random seed key...\n")
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
	}
	const max_depth = 3
	const max_child = 1

	var privateKey [max_depth][max_child][]byte
	var privateChainCode [max_depth][max_child][]byte
	var publicKey [max_depth][max_child][]byte
	var publicChainCode [max_depth][max_child][]byte
	var child, depth uint64

	fmt.Println("Depth0: Generating master key and master chaincode...")
	masterSecretKey, masterChainCode := bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032MASTERK,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	fmt.Println("Depth0: Generated master key from random seed and master chaincode")

	fmt.Println("Depth1: Generating Wallets accounts...")
	privateKey[0][0], privateChainCode[0][0] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		masterSecretKey,
		masterChainCode,
	)
	publicKey[0][0], publicChainCode[0][0] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		masterSecretKey,
		masterChainCode,
	)

	fmt.Println("Depth1: Generated external and internal Wallet accout")

	fmt.Println("Depth2: Generating Wallets chains...")
	privateKey[1][0], privateChainCode[1][0] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		privateKey[0][0],
		privateChainCode[0][0],
	)
	publicKey[1][0], publicChainCode[1][0] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		privateKey[0][0],
		privateChainCode[0][0],
	)

	fmt.Println("Depth2: Generated internal and external wallet chain successfully")

	fmt.Println("Depth3: Generating Wallets addresses...")
	privateKey[2][0], privateChainCode[2][0] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		privateKey[1][0],
		privateChainCode[1][0],
	)
	publicKey[2][0], publicChainCode[2][0] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		privateKey[1][0],
		privateChainCode[1][0],
	)
	fmt.Println("Depth3: Generated external and internal addresses successfully.")

	for depth = 0; depth < max_depth; depth++ {
		for child = 0; child < max_child; child++ {
			bip32_signAndVerify(cryptoClient, privateKey[depth][child], publicKey[depth][child])
		}
	}
	fmt.Println("Sign and verify")

	for depth = 0; depth < max_depth; depth++ {
		for child = 0; child < max_child; child++ {
			bip32_signAndVerifySingle(cryptoClient, privateKey[depth][child], publicKey[depth][child])
		}
	}
	fmt.Println("SignSingle and verifySingle")

	// Output:
	// Generating random seed key...
	// Depth0: Generating master key and master chaincode...
	// Derived Key type=CkBIP0032MASTERK index=0
	// Depth0: Generated master key from random seed and master chaincode
	// Depth1: Generating Wallets accounts...
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth1: Generated external and internal Wallet accout
	// Depth2: Generating Wallets chains...
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth2: Generated internal and external wallet chain successfully
	// Depth3: Generating Wallets addresses...
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth3: Generated external and internal addresses successfully.
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Sign and verify
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// Data signed
	// Signature verified
	// SignSingle and verifySingle
}

//cover private->private public->public key derivation
func Example_bip32_KeyDerivation() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	fmt.Printf("Generating random seed key...\n")
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
	}

	var publicKey []byte
	var publicChainCode []byte

	fmt.Println("Generating master key and master chaincode...")
	masterSecretKey, masterChainCode := bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032MASTERK,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	fmt.Println("Generated master key from random seed and master chaincode")

	fmt.Println("Generating Wallets accounts...")
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveSecp256k1)
	if err != nil {
		panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
	}
	publicKey, publicChainCode = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		masterSecretKey,
		masterChainCode,
	)
	fmt.Println("Derive key from private -> public")
	deriveKeyRequestPri := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_BTC_DERIVE,
			Parameter: &pb.Mechanism_BTCDeriveParameter{
				BTCDeriveParameter: &pb.BTCDeriveParm{
					Type:          pb.BTCDeriveParm_CkBIP0032PRV2PRV,
					ChildKeyIndex: 0,
					ChainCode:     masterChainCode,
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
		BaseKey: masterSecretKey,
	}
	_, err = cryptoClient.DeriveKey(context.Background(), deriveKeyRequestPri)
	if err != nil {
		fmt.Println("Don't supporte deriving key from pulic to public in current soft-hsm version")
	} else {
		fmt.Println("Derive key from private -> private")
	}

	deriveKeyRequestPub := &pb.DeriveKeyRequest{
		Mech: &pb.Mechanism{
			Mechanism: ep11.CKM_IBM_BTC_DERIVE,
			Parameter: &pb.Mechanism_BTCDeriveParameter{
				BTCDeriveParameter: &pb.BTCDeriveParm{
					Type:          pb.BTCDeriveParm_CkBIP0032PUB2PUB,
					ChildKeyIndex: 0,
					ChainCode:     publicChainCode,
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
		BaseKey: publicKey,
	}
	_, err = cryptoClient.DeriveKey(context.Background(), deriveKeyRequestPub)
	if err != nil {
		fmt.Println("Don't supporte deriving key from pulic -> public in current soft-hsm version")
	} else {
		fmt.Printf("Derive key from public to public successfully")
	}

	// Output:
	// Generating random seed key...
	// Generating master key and master chaincode...
	// Derived Key type=CkBIP0032MASTERK index=0
	// Generated master key from random seed and master chaincode
	// Generating Wallets accounts...
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Derive key from private -> public
	// Derive key from private -> private
	// Derive key from public to public successfully
}

//cross sign and verification
func Example_bip32_Cross_SignVerify() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	fmt.Printf("Generating random seed key...\n")
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
	}

	fmt.Println("Generating master key and master chaincode...")
	masterSecretKey, masterChainCode := bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032MASTERK,
		0,
		generateKeyResponse.KeyBytes,
		nil,
	)
	fmt.Println("Generated master key from random seed and master chaincode")

	var privateKey_w [3][]byte
	var privateChainCode_w [3][]byte
	var publicKey_w [3][]byte
	var publicChainCode_w [3][]byte

	privateKey_w[0], privateChainCode_w[0] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		masterSecretKey,
		masterChainCode,
	)
	publicKey_w[0], publicChainCode_w[0] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		masterSecretKey,
		masterChainCode,
	)
	fmt.Println("Depth1: Generated external and internal Wallet accout")
	bip32_signAndVerifySingle(cryptoClient, privateKey_w[0], publicKey_w[0])

	privateKey_w[1], privateChainCode_w[1] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		privateKey_w[0],
		privateChainCode_w[0],
	)
	publicKey_w[1], publicChainCode_w[1] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		privateKey_w[0],
		privateChainCode_w[0],
	)
	fmt.Println("Depth2: Generated internal and external wallet chain successfully")
	bip32_signAndVerifySingle(cryptoClient, privateKey_w[1], publicKey_w[1])

	privateKey_w[2], privateChainCode_w[2] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PRV,
		0,
		privateKey_w[1],
		privateChainCode_w[1],
	)
	publicKey_w[2], publicChainCode_w[2] = bip32_deriveKey(
		cryptoClient,
		pb.BTCDeriveParm_CkBIP0032PRV2PUB,
		0,
		privateKey_w[1],
		privateChainCode_w[1],
	)
	fmt.Println("Depth3: Generated external and internal addresses successfully.")
	bip32_signAndVerifySingle(cryptoClient, privateKey_w[2], publicKey_w[2])

	fmt.Println("Round 1: Cross verification")
	signData_1 := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest_1 := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privateKey_w[2],
		Data:    signData_1,
	}
	signSingleResponse_1, err := cryptoClient.SignSingle(context.Background(), signSingleRequest_1)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	verifySingleRequest_1 := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey:    publicKey_w[1],
		Data:      signData_1,
		Signature: signSingleResponse_1.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest_1)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("Round 1: Invalid signature")
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Round 2: Cross verification")
	signData_2 := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest_2 := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privateKey_w[1],
		Data:    signData_2,
	}
	signSingleResponse_2, err := cryptoClient.SignSingle(context.Background(), signSingleRequest_2)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	verifySingleRequest_2 := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey:    publicKey_w[0],
		Data:      signData_2,
		Signature: signSingleResponse_2.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest_2)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("Round 2: Invalid signature")
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	fmt.Println("Round 3: Cross verification")
	signData_3 := sha256.New().Sum([]byte("This data needs to be signed"))
	signSingleRequest_3 := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privateKey_w[0],
		Data:    signData_3,
	}
	signSingleResponse_3, err := cryptoClient.SignSingle(context.Background(), signSingleRequest_3)
	if err != nil {
		panic(fmt.Errorf("SignSingle error: %s", err))
	}

	verifySingleRequest_3 := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey:    publicKey_w[2],
		Data:      signData_3,
		Signature: signSingleResponse_3.Signature,
	}
	_, err = cryptoClient.VerifySingle(context.Background(), verifySingleRequest_3)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Println("Round 3: Invalid signature")
		} else {
			panic(fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	//Output:
	// Generating random seed key...
	// Generating master key and master chaincode...
	// Derived Key type=CkBIP0032MASTERK index=0
	// Generated master key from random seed and master chaincode
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth1: Generated external and internal Wallet accout
	// Data signed
	// Signature verified
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth2: Generated internal and external wallet chain successfully
	// Data signed
	// Signature verified
	// Derived Key type=CkBIP0032PRV2PRV index=0
	// Derived Key type=CkBIP0032PRV2PUB index=0
	// Depth3: Generated external and internal addresses successfully.
	// Data signed
	// Signature verified
	// Round 1: Cross verification
	// Round 1: Invalid signature
	// Round 2: Cross verification
	// Round 2: Invalid signature
	// Round 3: Cross verification
	// Round 3: Invalid signature
}

