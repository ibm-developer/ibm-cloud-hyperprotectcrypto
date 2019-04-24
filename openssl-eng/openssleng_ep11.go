/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

/*
#cgo CFLAGS: -std=c99 -I../common -Iopenssl-1.0.2r/crypto -g -O0 -Wall
#cgo darwin CFLAGS: -I/usr/local/opt/openssl/include
#cgo linux CFLAGS: -I/usr/local/openssl-1.0.2r/include

#cgo LDFLAGS: -lcrypto
#cgo darwin LDFLAGS: -L/usr/local/opt/openssl/lib
#cgo linux LDFLAGS: -L/usr/local/openssl-1.0.2r/lib

#include "nativeC/grep11.h"

//According https://github.com/golang/go/wiki/cgo, we can't define any C functions in preamble if you're using exports.
//So all openssl engine implementation is put in a separate C file.
*/
import "C"

import (
	"context"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	grpc "google.golang.org/grpc"
)

const (
	address = "address-to-ep11server.com"
)

/*RemoteGenerateECDSAKeyPair generate ECDSA key pairs.
For now only secp224r1 (P-224 under NIST name), secp256r1 (P-256), secp384r1 (P-384) and secp521r1 (P-521) are supported, which are also supported by golang elliptic package.
However, ep11 also support brainpool curve and brainpool twisted curves (page 10, reference):
EC objects are only supported based on specific curves (prime field, NIST [Nat13, D.1.2] or Brainpool [LM10, 3]),
therefore curve parameters are fixed, and may not be replaced by host-based attackers.
*/
//export RemoteGenerateECDSAKeyPair
func RemoteGenerateECDSAKeyPair(curveOIDData *C.uchar, curveOIDLength C.size_t, privateKey *C.uchar, privateKeyLen *C.size_t, pubKey *C.uchar, pubKeyLen *C.size_t) C.int {

	var nameCurvOID asn1.ObjectIdentifier
	asn1OID := C.GoBytes(unsafe.Pointer(curveOIDData), C.int(curveOIDLength))
	_, err := asn1.Unmarshal(asn1OID, &nameCurvOID)
	if err != nil {
		fmt.Printf("Unable to unmarshal cureve OID [%s]: %v\n", hex.Dump(asn1OID), err)
		return 0
	}

	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		fmt.Printf("Cannot connect: %v\n", err)
		return 0
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	//Generate ECDH key pairs.
	ecParameters, err := asn1.Marshal(nameCurvOID)
	if err != nil {
		fmt.Printf("Unable To Encode Parameter OID: %s\n", err)
		return 0
	}

	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
		util.NewAttribute(ep11.CKA_VERIFY, true), //to verify a signature
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_DERIVE, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
		util.NewAttribute(ep11.CKA_SIGN, true), //to generate signature
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
	}
	ecKeypairResponse, err := cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		fmt.Printf("Generate EC Key Pair Error: %s\n", err)
		return 0
	}

	var keyLen = len(ecKeypairResponse.PrivKey)
	if *privateKeyLen < C.size_t(keyLen) {
		fmt.Printf("Private key buffer (%d) is not big enought for key data (%d)\n", *privateKeyLen, keyLen)
		return 0
	}
	var pData = C.CBytes(ecKeypairResponse.PrivKey)
	*privateKeyLen = C.size_t(keyLen)
	C.memcpy(unsafe.Pointer(privateKey), pData, C.size_t(keyLen))
	C.free(pData)
	pData = nil

	pubKeyCoordinates, err := util.GetPubkeyBytesFromSPKI(ecKeypairResponse.PubKey)
	if err != nil {
		fmt.Printf("Failed to generate public key coordinates\n")
		return 0
	}

	keyLen = len(pubKeyCoordinates)
	if *pubKeyLen < C.size_t(keyLen) {
		fmt.Printf("Public key buffer (%d) is not big enought for key data (%d)\n", *pubKeyLen, keyLen)
		return 0
	}
	pData = C.CBytes(pubKeyCoordinates)
	*pubKeyLen = C.size_t(keyLen)
	C.memcpy(unsafe.Pointer(pubKey), pData, C.size_t(keyLen))
	C.free(pData)

	return 1
}

//RemoteSignSingle return signature
//export RemoteSignSingle
func RemoteSignSingle(privateKeyBlob *C.uchar, keyBlobLen C.size_t, dgst *C.uchar, dgstLen C.size_t,
	signature *C.uchar, signatureLen *C.size_t) int32 {

	if privateKeyBlob == nil || dgst == nil || signature == nil || signatureLen == nil {
		fmt.Printf("One of parameters is NULL\n")
		return 0
	}

	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		fmt.Printf("Cannot connect: %v\n", err)
		return 0
	}
	defer conn.Close()

	cryptoClient := pb.NewCryptoClient(conn)

	signData := C.GoBytes(unsafe.Pointer(dgst), C.int(dgstLen))
	keyBlob := C.GoBytes(unsafe.Pointer(privateKeyBlob), C.int(keyBlobLen))

	if signData == nil || len(signData) == 0 || keyBlob == nil || len(keyBlob) == 0 {
		fmt.Printf("Invalid parameter\n")
		return 0
	}
	//Sign data
	SignSingleRequest := &pb.SignSingleRequest{
		Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
		PrivKey: keyBlob,
		Data:    signData,
	}
	SignSingleResponse, err := cryptoClient.SignSingle(context.Background(), SignSingleRequest)
	if err != nil {
		fmt.Printf("SignSingle Error: %s", err)
		return 0
	}

	var dataLen = len(SignSingleResponse.Signature)
	if *signatureLen < C.size_t(dataLen) {
		fmt.Printf("Signature buffer (%d) is not big enough to for signature data (%d)\n", *signatureLen, dataLen)
		return 0
	}
	var pData = C.CBytes(SignSingleResponse.Signature)
	*signatureLen = C.size_t(dataLen)
	C.memcpy(unsafe.Pointer(signature), pData, C.size_t(dataLen))
	C.free(pData)
	return 1
}

func main() {
	// We need the main function to make possible
	// CGO compiler to compile the package as C shared library
}
