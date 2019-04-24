#ifndef _GREP11_H_
#define _GREP11_H_ 1

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include <unistd.h>
#include "pkcs11.h"

#include <stdint.h>
#include "ep11.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_APQN 256

struct ep11_target_t {
	short format;
	short length;
	short apqns[2*MAX_APQN];
} __attribute__((packed));

#define CKR_VENDOR_DEFINED_GREP11        CKR_VENDOR_DEFINED + 0x40000
#define CKR_IBM_GREP11_NOT_AUTHENTICATED CKR_VENDOR_DEFINED_GREP11 + 0x01
#define CKR_IBM_GREP11_CANNOT_UNMARSHAL  CKR_VENDOR_DEFINED_GREP11 + 0x02
#define CKR_IBM_GREP11_CANNOT_MARSHAL    CKR_VENDOR_DEFINED_GREP11 + 0x03
#define CKR_IBM_GREP11_CONFLICT          CKR_VENDOR_DEFINED_GREP11 + 0x04
#define CKR_IBM_GREP11_DBINTERNAL        CKR_VENDOR_DEFINED_GREP11 + 0x05
#define CKR_IBM_GREP11_SERVER_CONFIG     CKR_VENDOR_DEFINED_GREP11 + 0x06
#define CKR_IBM_GREP11_SERVER_INTERNAL   CKR_VENDOR_DEFINED_GREP11 + 0x07

#define CKA_VENDOR_DEFINED_GREP11 CKA_VENDOR_DEFINED + 0x40000
#define CKA_GREP11_RAW_KEYBLOB    CKA_VENDOR_DEFINED_GREP11 + 0x01
#endif
