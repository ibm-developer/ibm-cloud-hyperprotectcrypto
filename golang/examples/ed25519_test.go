package examples

import (
        "context"
        "crypto/sha256"
        "encoding/asn1"
        "fmt"
        "testing"
        "crypto/tls"
        "crypto/x509"
        "io/ioutil"
        yaml "gopkg.in/yaml.v2"

        "google.golang.org/grpc/credentials"
        "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
        pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
        "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
        "github.com/stretchr/testify/assert"
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

// testingX is an interface wrapper around golang type *testing.T and *testing.B
type testingX interface {
	Errorf(format string, args ...interface{})
	Logf(format string, args ...interface{})
}

func TestED25519NewMechanism(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)

	var newCKM map[string]ep11.Mechanism
	newCKM = map[string]ep11.Mechanism{
		// Add more mechanisms here
		"CKM_IBM_ED25519_SHA512": ep11.CKM_IBM_ED25519_SHA512,
	}

	mechanismListRequest := &pb.GetMechanismListRequest{}
	mechanismListResponse, err := cryptoClient.GetMechanismList(context.Background(), mechanismListRequest)
	if err != nil {
		t.Errorf("Get mechanism list error: %s", err)
	}
	for name, value := range newCKM {
		ok := false
		for _, v := range mechanismListResponse.Mechs {
			if value == v {
				ok = true
				break
			}
		}

		if ok {
			t.Logf("Testing GetMechanismList(), Checking [%s]: OK", name)
		} else {
			t.Errorf("Testing GetMechanismList(), Checking [%s]: FAILED", name)
		}
	}

	for name, value := range newCKM {
		mechanismInfoRequest := &pb.GetMechanismInfoRequest{
			Mech: value,
		}
		_, err = cryptoClient.GetMechanismInfo(context.Background(), mechanismInfoRequest)
		if err != nil {
			t.Errorf("Testing GetMechanismInfo(), Checking [%s]: FAILED", name)
		} else {
			t.Logf("Testing GetMechanismInfo(), Checking [%s]: OK", name)
		}
	}
}

func TestED25519SignVerify(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	generateKeyPairResponse, err := ed25519KeyGenerate(t, cryptoClient)
	assert.NoError(t, err)

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signature, err := ed25519KeySign(t, cryptoClient, generateKeyPairResponse.PrivKey, signData)
	assert.NoError(t, err)
	err = ed25519KeyVerify(t, cryptoClient, generateKeyPairResponse.PubKey, signData, signature)
	assert.NoError(t, err)
}

func TestED25519SignVerifyMulti(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	generateKeyPairResponse, err := ed25519KeyGenerate(t, cryptoClient)
	assert.NoError(t, err)

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signature, err := ed25519KeySignMulti(t, cryptoClient, generateKeyPairResponse.PrivKey, signData)
	assert.Contains(t, err.Error(), "SignUpdate error")

	err = ed25519KeyVerifyMulti(t, cryptoClient, generateKeyPairResponse.PubKey, signData, signature)
	assert.Contains(t, err.Error(), "VerifyUpdate error")
}

func TestED25519SignVerifySingle(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	generateKeyPairResponse, err := ed25519KeyGenerate(t, cryptoClient)
	assert.NoError(t, err)

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signature, err := ed25519KeySignSingle(t, cryptoClient, generateKeyPairResponse.PrivKey, signData)
	assert.NoError(t, err)

	err = ed25519KeyVerifySingle(t, cryptoClient, generateKeyPairResponse.PubKey, signData, signature)
	assert.NoError(t, err)
}

func ed25519KeyGenerate(x testingX, cryptoClient pb.CryptoClient) (*pb.GenerateKeyPairResponse, error) {
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveED25519)
	if err != nil {
		return nil, fmt.Errorf("Unable to encode parameter OID: %s", err)
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
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair error: %s", err)
	}
	x.Logf("Testing GenerateKeyPair(), Generated ED25519 PKCS key pair")

	return generateKeyPairResponse, nil
}

func ed25519KeySignSingle(x testingX, cryptoClient pb.CryptoClient, privKey []byte, signData []byte) (signature []byte, err error) {
	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PrivKey: privKey,
		Data:    signData,
	}
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		return nil, fmt.Errorf("SignSingle error: %s", err)
	}
	x.Logf("Testing SignSingle(), Data signed by using SignSingle() with ED25519 PKCS key pair")

	return signSingleResponse.Signature, nil
}

func ed25519KeyVerifySingle(x testingX, cryptoClient pb.CryptoClient, pubKey []byte, signData []byte, signature []byte) error {
	verifySingleRequest := &pb.VerifySingleRequest{
		Mech:      &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PubKey:    pubKey,
		Data:      signData,
		Signature: signature,
	}

	_, err := cryptoClient.VerifySingle(context.Background(), verifySingleRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			return fmt.Errorf("VerifySingle: Invalid signature")
		} else {
			return fmt.Errorf("VerifySingle error: [%d]: %s", ep11Status.Code, ep11Status.Detail)
		}
	}
	x.Logf("Testing VerifySingle(), ED25519 signature verified by using VerifySingle()")

	return nil
}

func ed25519KeySign(x testingX, cryptoClient pb.CryptoClient, privKey []byte, signData []byte) (signature []byte, err error) {
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PrivKey: privKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		return nil, fmt.Errorf("SignInit error: %s", err)
	}
	signRequest := &pb.SignRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	SignResponse, err := cryptoClient.Sign(context.Background(), signRequest)
	if err != nil {
		return nil, fmt.Errorf("Sign error: %s", err)
	}
	x.Logf("Testing SignInit() and Sign(), Data signed by using SignInit() and Sign() with ED25519 PKCS key pair")

	return SignResponse.Signature, nil
}

func ed25519KeySignMulti(x testingX, cryptoClient pb.CryptoClient, privKey []byte, signData []byte) (signature []byte, err error) {
	signInitRequest := &pb.SignInitRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PrivKey: privKey,
	}
	signInitResponse, err := cryptoClient.SignInit(context.Background(), signInitRequest)
	if err != nil {
		return nil, fmt.Errorf("SignInit error: %s", err)
	}

	signUpdateRequest := &pb.SignUpdateRequest{
		State: signInitResponse.State,
		Data:  signData,
	}
	signUpdateResponse, err := cryptoClient.SignUpdate(context.Background(), signUpdateRequest)
	if err != nil {
		return nil, fmt.Errorf("SignUpdate error: %s", err)
	}

	signFinalRequest := &pb.SignFinalRequest{
		State: signUpdateResponse.State,
	}
	signFinalResponse, err := cryptoClient.SignFinal(context.Background(), signFinalRequest)
	if err != nil {
		return nil, fmt.Errorf("SignFinal error: %s", err)
	}

	x.Logf("Testing SignInit(), SignUpdate() and SignFinal(), Data signed by using SignInit(), SignUpdate() and SignFinal() with ED25519 PKCS key pair")

	return signFinalResponse.Signature, nil
}

func ed25519KeyVerify(x testingX, cryptoClient pb.CryptoClient, pubKey []byte, signData []byte, signature []byte) error {
	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PubKey: pubKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		return fmt.Errorf("VerifyInit error: %s", err)
	}
	verifyRequest := &pb.VerifyRequest{
		State:     verifyInitResponse.State,
		Data:      signData,
		Signature: signature,
	}
	_, err = cryptoClient.Verify(context.Background(), verifyRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			return fmt.Errorf("Verify: Invalid signature")
		} else {
			return fmt.Errorf("Verify error: [%d]: %s", ep11Status.Code, ep11Status.Detail)
		}
	}
	x.Logf("Testing VerifyInit() and Verify(), ED25519 signature verified by using VerifyInit() and Verify()")

	return nil
}

func ed25519KeyVerifyMulti(x testingX, cryptoClient pb.CryptoClient, pubKey []byte, signData []byte, signature []byte) error {
	verifyInitRequest := &pb.VerifyInitRequest{
		Mech:   &pb.Mechanism{Mechanism: ep11.CKM_IBM_ED25519_SHA512},
		PubKey: pubKey,
	}
	verifyInitResponse, err := cryptoClient.VerifyInit(context.Background(), verifyInitRequest)
	if err != nil {
		return fmt.Errorf("VerifyInit error: %s", err)
	}

	verifyUpdateRequest := &pb.VerifyUpdateRequest{
		State: verifyInitResponse.State,
		Data:  signData,
	}
	verifyUpdateResponse, err := cryptoClient.VerifyUpdate(context.Background(), verifyUpdateRequest)
	if err != nil {
		return fmt.Errorf("VerifyUpdate error: %s", err)
	}

	verifyFinalRequest := &pb.VerifyFinalRequest{
		State:     verifyUpdateResponse.State,
		Signature: signature,
	}
	_, err = cryptoClient.VerifyFinal(context.Background(), verifyFinalRequest)
	if ok, ep11Status := util.Convert(err); !ok {
		if ep11Status.Code == ep11.CKR_SIGNATURE_INVALID {
			return fmt.Errorf("VerifyFinal: Invalid signature")
		} else {
			return fmt.Errorf("VerifyFinal error: [%d]: %s", ep11Status.Code, ep11Status.Detail)
		}
	}

	x.Logf("Testing VerifyInit(), VerifyUpdate() and VerifyFinal(), ED25519 signature verified by using VerifyInit(), VerifyUpdate() and VerifyFinal()")
	return nil
}

func TestED25519SignVerifyCrosstest(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	generateKeyPairResponse, err := ed25519KeyGenerate(t, cryptoClient)
	assert.NoError(t, err)

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signature, err := ed25519KeySignSingle(t, cryptoClient, generateKeyPairResponse.PrivKey, signData)
	assert.NoError(t, err)
	err = ed25519KeyVerify(t, cryptoClient, generateKeyPairResponse.PubKey, signData, signature)
	assert.NoError(t, err)

	signData = sha256.New().Sum([]byte("This data needs to be signed"))
	signature, err = ed25519KeySign(t, cryptoClient, generateKeyPairResponse.PrivKey, signData)
	assert.NoError(t, err)
	err = ed25519KeyVerifySingle(t, cryptoClient, generateKeyPairResponse.PubKey, signData, signature)
	assert.NoError(t, err)
}

// For negative test
func ecdsaKeyGenerate(x testingX, cryptoClient pb.CryptoClient) (*pb.GenerateKeyPairResponse, error) {
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		return nil, fmt.Errorf("Unable to encode parameter OID: %s", err)
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
	generateKeyPairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		return nil, fmt.Errorf("GenerateKeyPair error: %s", err)
	}
	x.Logf("Testing GenerateKeyPair(), Generated ECDSA PKCS key pair for negative test")

	return generateKeyPairResponse, nil
}

// For negative test
func ecdsaKeySignSingle(x testingX, cryptoClient pb.CryptoClient, privKey []byte, signData []byte) (signature []byte, err error) {
	signSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: privKey,
		Data:    signData,
	}
	signSingleResponse, err := cryptoClient.SignSingle(context.Background(), signSingleRequest)
	if err != nil {
		return nil, fmt.Errorf("SignSingle error: %s", err)
	}
	x.Logf("Testing SignSingle(), Data signed by using SignSingle() with ECDSA PKCS key pair for  negative test")

	return signSingleResponse.Signature, nil
}

func TestED25519InvalidKeyType(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	generateKeyPairResponseECDSA, err := ecdsaKeyGenerate(t, cryptoClient)
	assert.NoError(t, err)

	// Sign with the wrong key type
	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	signature, err := ed25519KeySignSingle(t, cryptoClient, generateKeyPairResponseECDSA.PrivKey, signData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SignSingle error")
	assert.Contains(t, err.Error(), "CKR_MECHANISM_INVALID")

	signature, err = ed25519KeySign(t, cryptoClient, generateKeyPairResponseECDSA.PrivKey, signData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SignInit error")
	assert.Contains(t, err.Error(), "CKR_MECHANISM_INVALID")

	signature, err = ed25519KeySignMulti(t, cryptoClient, generateKeyPairResponseECDSA.PrivKey, signData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SignInit error")
	assert.Contains(t, err.Error(), "CKR_MECHANISM_INVALID")

	// Verify with the wrong key type
	generateKeyPairResponseED25519, err := ed25519KeyGenerate(t, cryptoClient)
	assert.NoError(t, err)
	signature, err = ed25519KeySignSingle(t, cryptoClient, generateKeyPairResponseED25519.PrivKey, signData)
	assert.NoError(t, err)

	err = ed25519KeyVerifySingle(t, cryptoClient, generateKeyPairResponseECDSA.PubKey, signData, signature)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VerifySingle error")

	err = ed25519KeyVerify(t, cryptoClient, generateKeyPairResponseECDSA.PubKey, signData, signature)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VerifyInit error")
	assert.Contains(t, err.Error(), "CKR_MECHANISM_INVALID")

	err = ed25519KeyVerifyMulti(t, cryptoClient, generateKeyPairResponseECDSA.PubKey, signData, signature)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VerifyInit error")
	assert.Contains(t, err.Error(), "CKR_MECHANISM_INVALID")
}

func TestED25519InvalidKeys(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	keysWrong := []string{"wrong key", "", "~!@#$%^&*()_+-=|}{[';\":?/,.<>", "wrong key longggggggggggggggggggggggggggggggggg"}
	for _, keyWrong := range keysWrong {
		// Sign with the wrong key type
		signData := sha256.New().Sum([]byte("This data needs to be signed"))
		signature, err := ed25519KeySignSingle(t, cryptoClient, []byte(keyWrong), signData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SignSingle error")

		signature, err = ed25519KeySign(t, cryptoClient, []byte(keyWrong), signData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SignInit error")

		signature, err = ed25519KeySignMulti(t, cryptoClient, []byte(keyWrong), signData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SignInit error")

		// Verify with the wrong key
		generateKeyPairResponseED25519, err := ed25519KeyGenerate(t, cryptoClient)
		assert.NoError(t, err)
		signature, err = ed25519KeySignSingle(t, cryptoClient, generateKeyPairResponseED25519.PrivKey, signData)
		assert.NoError(t, err)

		err = ed25519KeyVerifySingle(t, cryptoClient, []byte(keyWrong), signData, signature)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VerifySingle error")

		err = ed25519KeyVerify(t, cryptoClient, []byte(keyWrong), signData, signature)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VerifyInit error")

		err = ed25519KeyVerifyMulti(t, cryptoClient, []byte(keyWrong), signData, signature)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VerifyInit error")
	}
}

func TestED25519InvalidSignature(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		panic(fmt.Errorf("Could not connect to server: %s", err))
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	signData := sha256.New().Sum([]byte("This data needs to be signed"))
	generateKeyPairResponseED25519, err := ed25519KeyGenerate(t, cryptoClient)
	assert.NoError(t, err)

	signature, err := ed25519KeySignSingle(t, cryptoClient, generateKeyPairResponseED25519.PrivKey, signData)
	assert.NoError(t, err)

	signatureWrong := []([]byte){
		[]byte(""),
		[]byte("Invalid signature..."),
		[]byte("~!@#$%^&*()_{}|:\"<>?/.,["),
		signature[:32],
		append(signature, signature...),
	}

	for _, signature := range signatureWrong {
		err = ed25519KeyVerify(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, signature)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Verify error")

		err = ed25519KeyVerifySingle(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, signature)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VerifySingle error")
	}

	rngTemplate := &pb.GenerateRandomRequest{Len: (uint64)(64)}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	assert.NoError(t, err)

	err = ed25519KeyVerify(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, rng.Rnd[:64])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Verify: Invalid signature")

	err = ed25519KeyVerifySingle(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, rng.Rnd[:64])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VerifySingle: Invalid signature")

	generateKeyPairResponseECDSA, err := ecdsaKeyGenerate(t, cryptoClient)
	assert.NoError(t, err)

	signature, err = ecdsaKeySignSingle(t, cryptoClient, generateKeyPairResponseECDSA.PrivKey, signData)
	assert.NoError(t, err)

	// Verify a ECDSA signature with ED25519 public key
	err = ed25519KeyVerify(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, signature)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature")

	err = ed25519KeyVerifySingle(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, signature)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature")

	//err = ed25519KeyVerifyMulti(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, signature)
	//assert.Error(t, err)
	//assert.Contains(t, err.Error(), "Invalid signature")

	err = ed25519KeyVerify(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Verify error")

	err = ed25519KeyVerifySingle(t, cryptoClient, generateKeyPairResponseED25519.PubKey, signData, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VerifySingle error")

}

func ed25519KeyGenerateChanWrap(t *testing.T, cryptoClient pb.CryptoClient, ch chan error) {
	_, err := ed25519KeyGenerate(t, cryptoClient)
	ch <- err
}

func ed25519KeySignChanWrap(t *testing.T, cryptoClient pb.CryptoClient, ch chan error, privKey []byte, signData []byte) {
	_, err := ed25519KeySign(t, cryptoClient, privKey, signData)
	ch <- err
}

func ed25519KeyVerifyChanWrap(t *testing.T, cryptoClient pb.CryptoClient, ch chan error, pubKey []byte, signData []byte, signature []byte) {
	err := ed25519KeyVerify(t, cryptoClient, pubKey, signData, signature)
	ch <- err
}

func ed25519KeySignSingleChanWrap(t *testing.T, cryptoClient pb.CryptoClient, ch chan error, privKey []byte, signData []byte) {
	_, err := ed25519KeySignSingle(t, cryptoClient, privKey, signData)
	ch <- err
}

func ed25519KeyVerifySingleChanWrap(t *testing.T, cryptoClient pb.CryptoClient, ch chan error, pubKey []byte, signData []byte, signature []byte) {
	err := ed25519KeyVerifySingle(t, cryptoClient, pubKey, signData, signature)
	ch <- err
}

func TestED25519ParallelGenerateKey(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		t.Errorf("Could not connect to server: %s", err)
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	chs := make([]chan error, 10)
	for i := 0; i < 10; i++ {
		chs[i] = make(chan error)
		go ed25519KeyGenerateChanWrap(t, cryptoClient, chs[i])
	}

	for _, ch := range chs {
		assert.NoError(t, <-ch)
	}
}

func TestED25519ParallelSignVerify(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		t.Errorf("Could not connect to server: %s", err)
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	generateKeyPairResponse, err := ed25519KeyGenerate(t, cryptoClient)
	assert.NoError(t, err)
	signData := sha256.New().Sum([]byte("This data needs to be signed"))

	chs := make([]chan error, 10)
	for i := 0; i < 10; i++ {
		chs[i] = make(chan error)
		go ed25519KeySignChanWrap(t, cryptoClient, chs[i], generateKeyPairResponse.PrivKey, signData)
	}

	for _, ch := range chs {
		assert.NoError(t, <-ch)
	}

	signature, err := ed25519KeySign(t, cryptoClient, generateKeyPairResponse.PrivKey, signData)
	assert.NoError(t, err)

	for i := 0; i < 10; i++ {
		chs[i] = make(chan error)
		go ed25519KeyVerifyChanWrap(t, cryptoClient, chs[i], generateKeyPairResponse.PubKey, signData, signature)
	}

	for _, ch := range chs {
		assert.NoError(t, <-ch)
	}
}

func TestED25519ParallelSignVerifySingle(t *testing.T) {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		t.Errorf("Could not connect to server: %s", err)
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	generateKeyPairResponse, err := ed25519KeyGenerate(t, cryptoClient)
	assert.NoError(t, err)
	signData := sha256.New().Sum([]byte("This data needs to be signed"))

	chs := make([]chan error, 10)
	for i := 0; i < 10; i++ {
		chs[i] = make(chan error)
		go ed25519KeySignSingleChanWrap(t, cryptoClient, chs[i], generateKeyPairResponse.PrivKey, signData)
	}

	for _, ch := range chs {
		assert.NoError(t, <-ch)
	}

	signature, err := ed25519KeySignSingle(t, cryptoClient, generateKeyPairResponse.PrivKey, signData)
	assert.NoError(t, err)

	for i := 0; i < 10; i++ {
		chs[i] = make(chan error)
		go ed25519KeyVerifySingleChanWrap(t, cryptoClient, chs[i], generateKeyPairResponse.PubKey, signData, signature)
	}

	for _, ch := range chs {
		assert.NoError(t, <-ch)
	}
}

