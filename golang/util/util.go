/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"google.golang.org/grpc/status"
)

var (
	lock sync.RWMutex
)

func init() {
	proto.RegisterType((*pb.Grep11Error)(nil), "grep11.Grep11Error")
}

// DumpAttributes converts an Attribute slice into a string of Attributes
func DumpAttributes(attrs map[ep11.Attribute][]byte) string {
	var buffer bytes.Buffer
	for _type, attr := range attrs {
		buffer.WriteString(fmt.Sprintf("[%s = %s]\n", _type, hex.EncodeToString(attr)))
	}
	return buffer.String()
}

// NewAttribute is a convenience function to make conversions to []C.CK_ATTRIBUTE more convenient
func NewAttribute(aType ep11.Attribute, val interface{}) *ep11.AttributeStruct {
	return &ep11.AttributeStruct{
		Type:  aType,
		Value: NewAttributeValue(val),
	}
}

// NewAttributeMap creates a map of ep11 attributes
func NewAttributeMap(attrs ...*ep11.AttributeStruct) map[ep11.Attribute][]byte {
	rc := make(map[ep11.Attribute][]byte)
	for _, val := range attrs {
		rc[val.Type] = val.Value
	}

	return rc
}

// NewAttributeValue converts a Golang-based attribute type to a C-based attribute type
func NewAttributeValue(val interface{}) []byte {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case bool:
		if v {
			return []byte{1}
		}
		return []byte{0}
	case string:
		return []byte(v)
	case []byte:
		return v
	default:
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, val)
		if err != nil {
			panic("PKCS11: Unhandled attribute type " + err.Error())
		}
		return buf.Bytes()
	}
}

// Convert returns a formatted GREP11 error message
// The contents of the error message depend on the source of the error
func Convert(err error) (bool, *pb.Grep11Error) {
	if err == nil {
		return true, nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Server returned error: [%s]", err),
			Retry:  true,
		}
	}

	detail := st.Details()
	if len(detail) != 1 {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Expected only one error: [%s]", err),
			Retry:  true,
		}
	}

	err2, ok := detail[0].(*pb.Grep11Error)
	if !ok {
		return false, &pb.Grep11Error{
			Code:   ep11.CKR_GENERAL_ERROR,
			Detail: fmt.Sprintf("Detail is the wrong type [%s]: [%s]", reflect.TypeOf(detail[0]), err),
			Retry:  true,
		}
	}

	return false, err2
}

var (
	// The following variables are standardized elliptic curve definitions
	OIDNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	OIDNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidECPublicKey    = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidRSAPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// GetNamedCurveFromOID returns an elliptic curve from the specified curve OID
func GetNamedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(OIDNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(OIDNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(OIDNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(OIDNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

// ecKeyIdentificationASN defines the ECDSA priviate/public key identifier for GREP11
type ecKeyIdentificationASN struct {
	KeyType asn1.ObjectIdentifier
	Curve   asn1.ObjectIdentifier
}

// ecPubKeyASN defines the ECDSA public key ASN1 encoding structure for GREP11
type ecPubKeyASN struct {
	Ident ecKeyIdentificationASN
	Point asn1.BitString
}

// generalKeyTypeASN is used to identify the public key ASN1 encoding structure for GREP11
type pubKeyTypeASN struct {
	KeyType asn1.ObjectIdentifier
}

// generalPubKeyASN is used to identify the public key type
type generalPubKeyASN struct {
	OIDAlgorithm pubKeyTypeASN
}

// GetPubKey converts an ep11 SPKI structure to a golang ecdsa.PublicKey
func GetPubKey(spki []byte) (crypto.PublicKey, asn1.ObjectIdentifier, error) {
	firstDecode := &generalPubKeyASN{}
	_, err := asn1.Unmarshal(spki, firstDecode)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmarshaling public key: %s", err)
	}

	if firstDecode.OIDAlgorithm.KeyType.Equal(oidECPublicKey) {
		decode := &ecPubKeyASN{}
		_, err := asn1.Unmarshal(spki, decode)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed unmarshaling public key: %s", err)
		}
		curve := GetNamedCurveFromOID(decode.Ident.Curve)
		if curve == nil {
			return nil, nil, fmt.Errorf("Unrecognized Curve from OID %v", decode.Ident.Curve)
		}
		x, y := elliptic.Unmarshal(curve, decode.Point.Bytes)
		if x == nil {
			return nil, nil, fmt.Errorf("failed unmarshalling public key.\n%s", hex.Dump(decode.Point.Bytes))
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, asn1.ObjectIdentifier(oidECPublicKey), nil

	} else if firstDecode.OIDAlgorithm.KeyType.Equal(oidRSAPublicKey) {
		return nil, nil, fmt.Errorf("RSA public key not supported yet")
	} else {
		return nil, nil, fmt.Errorf("Unrecognized public key type %v", firstDecode.OIDAlgorithm)
	}
}

// GetPubkeyBytesFromSPKI extracts a coordinate bit array from the public key in SPKI format
func GetPubkeyBytesFromSPKI(spki []byte) ([]byte, error) {
	decode := &ecPubKeyASN{}
	_, err := asn1.Unmarshal(spki, decode)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshaling public key: [%s]", err)
	}
	return decode.Point.Bytes, nil
}

// IAMPerRPCCredentials type defines the fields required for IBM Cloud IAM authentication
// This type implements the GRPC PerRPCCredentials interface
type IAMPerRPCCredentials struct {
	expiration  time.Time
	updateLock  sync.Mutex
	Instance    string // Always Required - IBM Cloud HPCS instance ID
	AccessToken string // Required if APIKey nor Endpoint are specified - IBM Cloud IAM access token
	APIKey      string // Required if AccessToken is not specified - IBM Cloud API key
	Endpoint    string // Required if AccessToken is not specified - IBM Cloud IAM endpoint
}

// GetRequestMetadata is used by GRPC for authentication
func (cr *IAMPerRPCCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	// Set token if empty or Set token if expired
	if len(cr.APIKey) != 0 && len(cr.Endpoint) != 0 && time.Now().After(cr.expiration) {
		if err := cr.getToken(ctx); err != nil {
			return nil, err
		}
	}

	return map[string]string{
		"authorization":    cr.AccessToken,
		"bluemix-instance": cr.Instance,
	}, nil
}

// RequireTransportSecurity is used by GRPC for authentication
func (cr *IAMPerRPCCredentials) RequireTransportSecurity() bool {
	return true
}

// getToken obtains a bearer token and its expiration
func (cr *IAMPerRPCCredentials) getToken(ctx context.Context) (err error) {
	cr.updateLock.Lock()
	defer cr.updateLock.Unlock()

	// Check if another thread has updated the token
	if time.Now().Before(cr.expiration) {
		return nil
	}

	var req *http.Request
	client := http.Client{}
	requestBody := []byte("grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=" + cr.APIKey)

	req, err = http.NewRequest("POST", cr.Endpoint+"/identity/token", bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %s", err)
	}
	defer resp.Body.Close()

	iamToken := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int32  `json:"expires_in"`
	}{}

	err = json.Unmarshal(respBody, &iamToken)
	if err != nil {
		return fmt.Errorf("error unmarshaling response body: %s", err)
	}

	cr.AccessToken = fmt.Sprintf("Bearer %s", iamToken.AccessToken)
	cr.expiration = time.Now().Add((time.Duration(iamToken.ExpiresIn - 60)) * time.Second)

	return nil
}
