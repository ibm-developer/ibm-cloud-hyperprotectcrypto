/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ep11

const (
	// Maximum Key Size
	MAX_BLOB_SIZE = 8192

	MAX_CSUMSIZE = 64

	// Max block size of block ciphers
	MAX_BLOCK_SIZE = 256 / 8
	AES_BLOCK_SIZE = 16
	DES_BLOCK_SIZE = 8

	// Max digest output bytes
	MAX_DIGEST_BYTES = 512 / 8

	// MAX_DIGEST_STATE_BYTES is the maximum size of wrapped digest state blobs
	//   -- Section 10.1 Function descriptions, EP11 design Document
	MAX_DIGEST_STATE_BYTES = 1024
	MAX_CRYPT_STATE_BYTES  = 8192

	CK_UNAVAILABLE_INFORMATION uint64 = 0xFFFFFFFFFFFFFFFF
)
