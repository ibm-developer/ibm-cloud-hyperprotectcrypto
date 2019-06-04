/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"google.golang.org/grpc/status"
)

var (
	lock sync.RWMutex
)

func init() {
	//FIXME: there is a discrepancy here between gogo.proto.RegisterType and standard golang proto
	//this is for now sufficient to get Grep11Error and grpc/status working, but need to reconcile
	//hint one: us github.com/gogo/status
	//hint two: stop using gogo generation, if casting can be fixed
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

// NewAttribute is a convenience function to golang code to make conversions
// to []C.CK_ATTRIBUTE more convenient
func NewAttribute(aType ep11.Attribute, val interface{}) *ep11.AttributeStruct {
	return &ep11.AttributeStruct{
		Type:  aType,
		Value: NewAttributeValue(val),
	}
}

// NewAttribute is a convenience function to golang code to make conversions
// to []C.CK_ATTRIBUTE more convenient
// This should really live in test_helpers
func NewAttributeMap(attrs ...*ep11.AttributeStruct) map[ep11.Attribute][]byte {
	rc := make(map[ep11.Attribute][]byte)
	for _, val := range attrs {
		rc[val.Type] = val.Value
	}

	return rc
}

func NewAttributeValue(val interface{}) []byte {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case bool:
		if v {
			return []byte{1}
		} else {
			return []byte{0}
		}
	case string:
		return []byte(v)
	case []byte:
		return v
		//	case KeyType:
		//		return []byte{byte(v)}
		//	case ObjectClass:
		//		return []byte{byte(v)}
		//	case uint:
		//		ul := C.CK_ULONG(v)
		//		return C.GoBytes(unsafe.Pointer(&ul), C.int(unsafe.Sizeof(ul)))
		//	case KeyType:
		//		castArr := *(*[4]byte)(unsafe.Pointer(&v))
		//		return castArr[:]
	//case time.Time: // for CKA_DATE
	//	panic("PKCS11: Unimplemented, CKA_DATE not yet supported")
	default:
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.BigEndian, val)
		//err := binary.Write(buf, binary.LittleEndian, val)
		if err != nil {
			//TODO: Need another way to handle errors when creating Attribute objects
			panic("PKCS11: Unhandled attribute type " + err.Error())
		}
		return buf.Bytes()
	}
}

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
	OIDNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	OIDNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} //prime256v1
	OIDNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidECPublicKey    = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidRSAPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

//GetNamedCurveFromOID returns Curve from specified curve OID
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

//ecKeyIdentificationASN defines the ECDSA priviate/public key identifier for ep11
type ecKeyIdentificationASN struct {
	KeyType asn1.ObjectIdentifier
	Curve   asn1.ObjectIdentifier
}

//ecPubKeyASN defines ECDSA public key ASN1 encoding structure for ep11
type ecPubKeyASN struct {
	Ident ecKeyIdentificationASN
	Point asn1.BitString
}

type pubKeyTypeASN struct {
	KeyType asn1.ObjectIdentifier
}

//generalPubKeyASN used to identify the public key type
type generalPubKeyASN struct {
	OIDAlgorithm pubKeyTypeASN
}

//GetPubKey convert ep11 SPKI structure to golang ecdsa.PublicKey
func GetPubKey(spki []byte) (crypto.PublicKey, asn1.ObjectIdentifier, error) {
	firstDecode := &generalPubKeyASN{}
	_, err := asn1.Unmarshal(spki, firstDecode)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmarshalling public key: %s", err)
	}

	if firstDecode.OIDAlgorithm.KeyType.Equal(oidECPublicKey) {
		decode := &ecPubKeyASN{}
		_, err := asn1.Unmarshal(spki, decode)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed unmarshalling public key: %s", err)
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

//GetPubkeyBytesFromSPKI extracts coordinates bit array from public key in SPKI format
func GetPubkeyBytesFromSPKI(spki []byte) ([]byte, error) {
	decode := &ecPubKeyASN{}
	_, err := asn1.Unmarshal(spki, decode)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshalling public key: [%s]", err)
	}
	return decode.Point.Bytes, nil
}
