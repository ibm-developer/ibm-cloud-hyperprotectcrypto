package examples

import (
	"bytes"
	"context"
	"encoding/asn1"
	"fmt"
	"reflect"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	uuid "github.com/satori/go.uuid"
	grpc "google.golang.org/grpc"
)

const (
	address = "your-ep11server-address.com:12345"
)

// Example_getMechnismInfo gets mechnism list and retrieve detail information for CKM_RSA_PKCS
func Example_getMechnismInfo() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	mechanismListRequest := &pb.GetMechanismListRequest{}
	mechanismListResponse, err := cryptoClient.GetMechanismList(context.Background(), mechanismListRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism list error: %s", err))
	}
	fmt.Printf("Got mechanism list:\n%v ...\n", mechanismListResponse.Mechs[:5])

	mechanismInfoRequest := &pb.GetMechanismInfoRequest{
		Mech: ep11.CKM_RSA_PKCS,
	}
	_, err = cryptoClient.GetMechanismInfo(context.Background(), mechanismInfoRequest)
	if err != nil {
		panic(fmt.Errorf("Get mechanism info error: %s", err))
	}

	// Output:
	// Got mechanism list:
	// [CKM_RSA_PKCS CKM_RSA_PKCS_KEY_PAIR_GEN CKM_RSA_X9_31_KEY_PAIR_GEN CKM_RSA_PKCS_PSS CKM_SHA1_RSA_X9_31] ...
}

//Example_encryptAndecrypt encrypt and decrypt a piece of text.
func Example_encryptAndecrypt() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)
	keyLen := 128
	keyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(keyLen/8)),
		util.NewAttribute(ep11.CKA_WRAP, false), // will you call wrap/unwrap?
		util.NewAttribute(ep11.CKA_UNWRAP, false),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false), // set to false!
		util.NewAttribute(ep11.CKA_TOKEN, true),        // ignored by EP11
	)

	keygenmsg := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: keyTemplate,
		KeyId:    uuid.NewV4().String(), //optional
	}

	generateKeyStatus, err := cryptoClient.GenerateKey(context.Background(), keygenmsg)
	if err != nil {
		panic(fmt.Errorf("GenerateKey Error: %s", err))
	}
	fmt.Println("Generated AES Key")

	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	fmt.Println("Generated IV")

	encipherInitInfo := &pb.EncryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: iv},
		Key:  generateKeyStatus.Key, // you may want to store this out
	}
	cipherStateInit, err := cryptoClient.EncryptInit(context.Background(), encipherInitInfo)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptInit [%s]", err))
	}

	plain := []byte("Hello, this is a very long and creative message without any imagination")

	encipherDataUpdate := &pb.EncryptUpdateRequest{
		State: cipherStateInit.State,
		Plain: plain[:20],
	}
	encipherStateUpdate, err := cryptoClient.EncryptUpdate(context.Background(), encipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	ciphertext := encipherStateUpdate.Ciphered[:]
	encipherDataUpdate = &pb.EncryptUpdateRequest{
		State: encipherStateUpdate.State,
		Plain: plain[20:],
	}
	encipherStateUpdate, err = cryptoClient.EncryptUpdate(context.Background(), encipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	ciphertext = append(ciphertext, encipherStateUpdate.Ciphered...)
	encipherDataFinal := &pb.EncryptFinalRequest{
		State: encipherStateUpdate.State,
	}
	encipherStateFinal, err := cryptoClient.EncryptFinal(context.Background(), encipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptFinal [%s]", err))
	}

	ciphertext = append(ciphertext, encipherStateFinal.Ciphered...)
	fmt.Println("Encrypted message")

	decipherInitInfo := &pb.DecryptInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: iv},
		Key:  generateKeyStatus.Key, // you may want to store this out
	}
	decipherStateInit, err := cryptoClient.DecryptInit(context.Background(), decipherInitInfo)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptInit [%s]", err))
	}

	decipherDataUpdate := &pb.DecryptUpdateRequest{
		State:    decipherStateInit.State,
		Ciphered: ciphertext[:16],
	}
	decipherStateUpdate, err := cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptUpdate [%s]", err))
	}

	plaintext := decipherStateUpdate.Plain[:]
	decipherDataUpdate = &pb.DecryptUpdateRequest{
		State:    decipherStateUpdate.State,
		Ciphered: ciphertext[16:],
	}
	decipherStateUpdate, err = cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptUpdate [%s]", err))
	}
	plaintext = append(plaintext, decipherStateUpdate.Plain...)

	decipherDataFinal := &pb.DecryptFinalRequest{
		State: decipherStateUpdate.State,
	}
	decipherStateFinal, err := cryptoClient.DecryptFinal(context.Background(), decipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed DecryptFinal [%s]", err))
	}
	plaintext = append(plaintext, decipherStateFinal.Plain...)

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing plain text of cipher single"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)

	// Output:
	// Generated AES Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message without any imagination
}

// Example_digest calculate digest on a piece of text
func Example_digest() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	digestData := []byte("This is the data longer than 64 bytes This is the data longer than 64 bytes")
	digestInitRequest := &pb.DigestInitRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_SHA256},
	}
	digestInitResponse, err := cryptoClient.DigestInit(context.Background(), digestInitRequest)
	if err != nil {
		panic(fmt.Errorf("Digest init error: %s", err))
	}
	digestRequest := &pb.DigestRequest{
		State: digestInitResponse.State,
		Data:  digestData,
	}
	digestResponse, err := cryptoClient.Digest(context.Background(), digestRequest)
	if err != nil {
		panic(fmt.Errorf("Digest error: %s", err))
	} else {
		fmt.Printf("Digest data using single digest operation: %x\n", digestResponse.Digest)
	}
	//Digest using mutiple operations
	digestInitResponse, err = cryptoClient.DigestInit(context.Background(), digestInitRequest)
	if err != nil {
		panic(fmt.Errorf("Digest init error: %s", err))
	}
	digestUpdateRequest := &pb.DigestUpdateRequest{
		State: digestInitResponse.State,
		Data:  digestData[:64],
	}
	digestUpdateResponse, err := cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Digest update error: %s", err))
	}
	digestUpdateRequest = &pb.DigestUpdateRequest{
		State: digestUpdateResponse.State,
		Data:  digestData[64:],
	}
	digestUpdateResponse, err = cryptoClient.DigestUpdate(context.Background(), digestUpdateRequest)
	if err != nil {
		panic(fmt.Errorf("Digest Update Error: %s", err))
	}
	digestFinalRequestInfo := &pb.DigestFinalRequest{
		State: digestUpdateResponse.State,
	}
	digestFinalResponse, err := cryptoClient.DigestFinal(context.Background(), digestFinalRequestInfo)
	if err != nil {
		panic(fmt.Errorf("Digest Final Error: %s", err))
	} else {
		fmt.Printf("Digest data using multiple operations: %x\n", digestFinalResponse.Digest)
	}

	// Output:
	// Digest data using single digest operation: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
	// Digest data using multiple operations: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
}

// Example_signAndVerifyUsingRSAKeyPair sign on a piece of data and verify it
func Example_signAndVerifyUsingRSAKeyPair() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	//Generate RSA key pairs
	publicExponent := []byte{0x11}
	publicKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_VERIFY, true), //to verify a signature
		util.NewAttribute(ep11.CKA_MODULUS_BITS, uint64(2048)),
		util.NewAttribute(ep11.CKA_PUBLIC_EXPONENT, publicExponent),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_PRIVATE, true),
		util.NewAttribute(ep11.CKA_SENSITIVE, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_SIGN, true), //to generate signature
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyTemplate,
		PrivKeyTemplate: privateKeyTemplate,
		PrivKeyId:       uuid.NewV4().String(),
		PubKeyId:        uuid.NewV4().String(),
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair Error: %s", err))
	}
	fmt.Println("Generated RSA PKCS key pairs")

	//Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_SHA1_RSA_PKCS},
		PrivKey: generateKeyPairStatus.PrivKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit Error: %s", err))
	}
	signData := []byte("These data need to be signed")
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign Error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_SHA1_RSA_PKCS},
		PubKey: generateKeyPairStatus.PubKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit Error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: SignResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid Signature\n"))
		} else {
			panic(fmt.Errorf("Verify Error[%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}
	fmt.Println("Verified")

	// Output:
	// Generated RSA PKCS key pairs
	// Data signed
	// Verified
}

// Example_signAndVerifyUsingECDSAKeyPair sign on a piece of data and verify it
func Example_signAndVerifyUsingECDSAKeyPair() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable To Encode Parameter OID: %s", err))
	}

	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_VERIFY, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_SIGN, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair Error: %s", err))
	}

	fmt.Println("Generated ECDSA PKCS key pairs")

	//Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairStatus.PrivKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit Error: %s", err))
	}
	signData := []byte("These data need to be signed")
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign Error: %s", err))
	}
	fmt.Println("Data signed")

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: generateKeyPairStatus.PubKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit Error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: SignResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			panic(fmt.Errorf("Invalid Signature\n"))
		} else {
			panic(fmt.Errorf("Verify Error[%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}
	fmt.Println("Verified")

	// Output:
	// Generated ECDSA PKCS key pairs
	// Data signed
	// Verified
}

// Example_signAndVerifyToTestErrorHandling sign on a piece of data, modify signature and verify it expecting error code returned
func Example_signAndVerifyToTestErrorHandling() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable To Encode Parameter OID: %s", err))
	}

	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_VERIFY, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_SIGN, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair Error: %s", err))
	}

	fmt.Println("Generated ECDSA PKCS key pairs")

	//Sign data
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: generateKeyPairStatus.PrivKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		panic(fmt.Errorf("SignInit Error: %s", err))
	}
	signData := []byte("These data need to be signed")
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		panic(fmt.Errorf("Sign Error: %s", err))
	}
	fmt.Println("Data signed")

	//modify signature to get error code
	SignResponse.Signature[0] = 255

	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PubKey: generateKeyPairStatus.PubKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		panic(fmt.Errorf("VerifyInit Error: %s", err))
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: SignResponse.Signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)

	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			fmt.Printf("Invalid Signature\n")
			return
		} else {
			panic(fmt.Errorf("Verify Error[%d]: %s", ep11Status.Code, ep11Status.Detail))
		}
	}

	// Output:
	// Generated ECDSA PKCS key pairs
	// Data signed
	// Invalid Signature
}

//Example_wrapAndUnWrapKey wraps a AES key with RSA public key and unwrap it with private key
func Example_wrapAndUnwrapKey() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	//Generate a AES key
	desKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(128/8)),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, true), // must be true to be wrapped
	)
	generateKeyRequest := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: desKeyTemplate,
		KeyId:    uuid.NewV4().String(), //optional
	}
	generateNewKeyStatus, err := cryptoClient.GenerateKey(context.Background(), generateKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Generate AES Key Error: %s", err))
	} else {
		fmt.Println("Generated AES key")
	}

	//Generate RSA key pairs
	publicExponent := []byte{0x11}
	publicKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_WRAP, true), //to wrap a key
		util.NewAttribute(ep11.CKA_MODULUS_BITS, uint64(2048)),
		util.NewAttribute(ep11.CKA_PUBLIC_EXPONENT, publicExponent),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_PRIVATE, true),
		util.NewAttribute(ep11.CKA_SENSITIVE, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_UNWRAP, true), //to unwrap a key
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyTemplate,
		PrivKeyTemplate: privateKeyTemplate,
		PrivKeyId:       uuid.NewV4().String(),
		PubKeyId:        uuid.NewV4().String(),
	}
	generateKeyPairStatus, err := cryptoClient.GenerateKeyPair(context.Background(), generateKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("GenerateKeyPair Error: %s", err))
	}
	fmt.Println("Generated PKCS key pairs")

	wrapKeyRequest := &pb.WrapKeyRequest{
		Mech: &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:  generateKeyPairStatus.PubKey,
		Key:  generateNewKeyStatus.Key,
	}
	wrapKeyResponse, err := cryptoClient.WrapKey(context.Background(), wrapKeyRequest)
	if err != nil {
		panic(fmt.Errorf("Wrap AES key error: %s", err))
	}
	fmt.Println("Wraped AES key")

	desUnwrapKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_CLASS, ep11.CKO_SECRET_KEY),
		util.NewAttribute(ep11.CKA_KEY_TYPE, ep11.CKK_AES),
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(128/8)),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, true), // must be true to be wrapped
	)
	unwrapRequest := &pb.UnwrapKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_RSA_PKCS},
		KeK:      generateKeyPairStatus.PrivKey,
		Wrapped:  wrapKeyResponse.Wrapped,
		Template: desUnwrapKeyTemplate,
	}
	unWrapedResponse, err := cryptoClient.UnwrapKey(context.Background(), unwrapRequest)
	if err != nil {
		panic(fmt.Errorf("Unwrap AES key error: %s", err))
	}
	if !bytes.Equal(generateNewKeyStatus.GetCheckSum()[:3], unWrapedResponse.GetCheckSum()[:3]) {
		panic(fmt.Errorf("Unwrap AES Key Has Different Checksum from Original Key"))
	} else {
		fmt.Println("Unwraped AES key")
	}

	// Output:
	// Generated AES key
	// Generated PKCS key pairs
	// Wraped AES key
	// Unwraped AES key
}

//Example_deriveKey generates ECDH key pairs for Bob and Alice, then generates AES keys for both of them.
//The name Alice and Bob are from https://en.wikipedia.org/wiki/Diffie–Hellman_key_exchange.
func Example_deriveKey() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	//Generate ECDH key pairs for Alice and Bob
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		panic(fmt.Errorf("Unable To Encode Parameter OID: %s", err))
	}

	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_DERIVE, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
	}
	aliceECKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("Generate Alice EC Key Pair Error: %s", err))
	}
	fmt.Println("Generated Alice EC key pairs")

	bobECKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		panic(fmt.Errorf("Generate Bob EC Key Pair Error: %s", err))
	}
	fmt.Println("Generated Bob EC key pairs")

	//Derive AES key for Alice
	deriveKeyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_CLASS, uint64(ep11.CKO_SECRET_KEY)),
		util.NewAttribute(ep11.CKA_KEY_TYPE, uint64(ep11.CKK_AES)),
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(128/8)),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
	)
	combinedCoordinates, err := util.GetPubkeyBytesFromSPKI(bobECKeypairResponse.PubKey)
	if err != nil {
		panic(fmt.Errorf("Bob EC Key Cannot Get Coordinates: %s", err))
	}
	aliceDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: combinedCoordinates},
		Template: deriveKeyTemplate,
		BaseKey:  aliceECKeypairResponse.PrivKey,
	}
	aliceDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), aliceDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Alice EC Key Derive Error: %s", err))
	}

	//Derive AES key for Bob
	combinedCoordinates, err = util.GetPubkeyBytesFromSPKI(aliceECKeypairResponse.PubKey)
	if err != nil {
		panic(fmt.Errorf("Alice EC Key Cannot Get Coordinates: %s", err))
	}
	bobDerivekeyRequest := &pb.DeriveKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_ECDH1_DERIVE, Parameter: combinedCoordinates},
		Template: deriveKeyTemplate,
		BaseKey:  bobECKeypairResponse.PrivKey,
	}
	bobDerivekeyResponse, err := cryptoClient.DeriveKey(context.Background(), bobDerivekeyRequest)
	if err != nil {
		panic(fmt.Errorf("Bob EC Key Derive Error: %s", err))
	}

	//encrypt with Alice's key and decrypt with Bob's key
	var msg = []byte("hello world!")
	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s", err))
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	encryptRequest := &pb.EncryptSingleRequest{
		Key:   aliceDerivekeyResponse.NewKey,
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: iv},
		Plain: msg,
	}
	encryptResponse, err := cryptoClient.EncryptSingle(context.Background(), encryptRequest)
	if err != nil {
		panic(fmt.Errorf("Encrypt Error: %s", err))
	}

	decryptRequest := &pb.DecryptSingleRequest{
		Key:      bobDerivekeyResponse.NewKey,
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: iv},
		Ciphered: encryptResponse.Ciphered,
	}
	decryptResponse, err := cryptoClient.DecryptSingle(context.Background(), decryptRequest)
	if err != nil {
		panic(fmt.Errorf("Decrypt Error: %s", err))
	}

	if !bytes.Equal(decryptResponse.Plain, msg) {
		panic(fmt.Errorf("Decrypted message[%v] is different from original one[%v]", decryptResponse.Plain, msg))
	} else {
		fmt.Println("Alice and Bob get same derived key")
	}

	return

	// Output:
	// Generated Alice EC key pairs
	// Generated Bob EC key pairs
	// Alice and Bob get same derived key
}
