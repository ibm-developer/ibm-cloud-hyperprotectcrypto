package main

import (
	"fmt"
	"reflect"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

func exampleStreamingCipher(conn *grpc.ClientConn) {
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
		panic(fmt.Errorf("GenerateKey Error: %s\n", err))
	}
	fmt.Println("Generated AES Key")

	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		panic(fmt.Errorf("GenerateRandom Error: %s\n", err))
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
	//fmt.Printf("Encrypted message\n%s\n%v\n", plain, ciphertext)
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
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}

	plaintext := decipherStateUpdate.Plain[:]
	decipherDataUpdate = &pb.DecryptUpdateRequest{
		State:    decipherStateUpdate.State,
		Ciphered: ciphertext[16:],
	}
	decipherStateUpdate, err = cryptoClient.DecryptUpdate(context.Background(), decipherDataUpdate)
	if err != nil {
		panic(fmt.Errorf("Failed Encrypt [%s]", err))
	}
	plaintext = append(plaintext, decipherStateUpdate.Plain...)

	decipherDataFinal := &pb.DecryptFinalRequest{
		State: decipherStateUpdate.State,
	}
	decipherStateFinal, err := cryptoClient.DecryptFinal(context.Background(), decipherDataFinal)
	if err != nil {
		panic(fmt.Errorf("Failed EncryptFinal [%s]", err))
	}
	plaintext = append(plaintext, decipherStateFinal.Plain...)

	if !reflect.DeepEqual(plain, plaintext) {
		panic(fmt.Errorf("Failed comparing plain text of cipher single"))
	}

	fmt.Printf("Decrypted message\n%s\n", plaintext)
	// Output :
	// Generated AES Key
	// Generated IV
	// Encrypted message
	// Decrypted message
	// Hello, this is a very long and creative message without any imagination
}

const (
	address = "localhost:9876"
)

func main() {
	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(fmt.Errorf("did not connect: %v", err))
	}
	defer conn.Close()

	exampleStreamingCipher(conn)
}
