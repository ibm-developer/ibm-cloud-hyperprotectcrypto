/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"bytes"
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
