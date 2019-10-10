/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"context"
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
)

// EP11PrivateKey MUST implement crypto.Signer interface so that the crypt/tls package can use
// an EP11PrivateKey in tls.Certificate: https://golang.org/pkg/crypto/tls/#Certificate
type EP11PrivateKey struct {
	algorithmOID asn1.ObjectIdentifier
	keyBlob      []byte
	pubKey       crypto.PublicKey // &ecdsa.PublicKey{} (rsa PublicKey not support yet)
	cryptoClient pb.CryptoClient
}

// Sign returns a signature in ASN1 format
// Reference code crypto/ecdsa.go, func (priv *PrivateKey) Sign() ([]byte, error)
func (priv *EP11PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	type ecdsaSignature struct {
		R, S *big.Int
	}
	if priv.algorithmOID.Equal(oidECPublicKey) {
		SignSingleRequest := &pb.SignSingleRequest{
			Mech:    &pb.Mechanism{Mechanism: ep11.CKM_ECDSA},
			PrivKey: priv.keyBlob,
			Data:    digest,
		}
		SignSingleResponse, err := priv.cryptoClient.SignSingle(context.Background(), SignSingleRequest)
		if err != nil {
			return nil, fmt.Errorf("SignSingle Error: %s", err)
		}
		// ep11 returns a raw signature byte array that must be encoded to ASN1 for tls package usage.
		var sigLen = len(SignSingleResponse.Signature)
		if sigLen%2 != 0 {
			return nil, fmt.Errorf("Signature length is not even: [%d]", sigLen)
		}
		r := new(big.Int)
		s := new(big.Int)

		r.SetBytes(SignSingleResponse.Signature[0 : sigLen/2])
		s.SetBytes(SignSingleResponse.Signature[sigLen/2:])
		return asn1.Marshal(ecdsaSignature{r, s})
	} else if priv.algorithmOID.Equal(oidRSAPublicKey) {
		return nil, fmt.Errorf("RSA public key is currently not supported")
	} else {
		return nil, fmt.Errorf("Unsupported Public key type: %v", priv.algorithmOID)
	}
}

//Public is part of the crypto.Signer interface implementation
func (priv *EP11PrivateKey) Public() crypto.PublicKey {
	return priv.pubKey
}

// NewEP11Signer is used in the creation of a TLS certificate
func NewEP11Signer(cryptoClient pb.CryptoClient, privKeyBlob []byte, spki []byte) (*EP11PrivateKey, error) {
	pubKey, oidAlg, err := GetPubKey(spki)
	if err != nil {
		return nil, fmt.Errorf("Failed to get public key: %s", err)
	}
	priv := &EP11PrivateKey{
		cryptoClient: cryptoClient,
		keyBlob:      privKeyBlob,
		algorithmOID: oidAlg,
		pubKey:       pubKey,
	}
	return priv, nil
}
