# Overview

1. Install the following two python packages: `asn1` and `grpcio-tools`

   	```
        $ pip3 install asn1 grpcio-tools
        ```

2. Update the following information in the [examples/server.py](examples/server.py#L14) file.  

	*NOTE: This information can obtained by logging in to your IBM Cloud account and viewing your Hyper Protect Crypto Serverices (HPCS) instance and IAM information. See the [GREP11 API documentation](https://cloud.ibm.com/docs/services/hs-crypto?topic=hs-crypto-grep11-api-ref) for more information about GREP11*.

	```Python
	# The following IBM Cloud items need to be changed prior to running the sample program
	address = "<grep11_server_address>:<port>"

	credentials = {
	    'APIKey':   "<ibm_cloud_apikey>",
	    'Endpoint': "<https://<iam_ibm_cloud_endpoint>",
	    'Instance': "<hpcs_instance_id>"
	}
	```
3. Go to `ibm-cloud-hyperprotectcrypto/python/examples`

4. Execute the following command to generate python bindings to access a grep11 server.

   	```Bash
	$ python3 -m grpc_tools.protoc ../grpc/common/protos/*.proto \
	     ../grpc/generated/protos/*.proto \
	     ../grpc/vendor/github.com/gogo/protobuf/gogoproto/*.proto \
             ../grpc/vendor/github.com/gogo/googleapis/google/api/*.proto \
             -I../grpc/common/protos -I../grpc/generated/protos \
             -I../grpc/vendor/github.com/gogo/protobuf/gogoproto \
             -I../grpc/vendor/github.com/gogo/googleapis \
             --python_out=. --grpc_python_out=.
	```

5. Execute the examples by issuing the command: `python3 -m unittest -b -v`
6. The sample program produces output similar to the following:

        ```
        $ python3 -m unittest -b -v
        test_0_getMechanismInfo (test_server.ServerTestCase) ... ok
        test_1_encryptAndDecrypt (test_server.ServerTestCase) ... ok
        test_2_digest (test_server.ServerTestCase) ... ok
        test_3_signAndVerifyUsingRSAKeyPair (test_server.ServerTestCase) ... ok
        test_4_signAndVerifyUsingECDSAKeyPair (test_server.ServerTestCase) ... ok
        test_5_signAndVerifyToTestErrorHandling (test_server.ServerTestCase) ... expected failure
        test_6_wrapAndUnwrapKey (test_server.ServerTestCase) ... ok
        test_7_deriveKey (test_server.ServerTestCase) ... ok

        ----------------------------------------------------------------------
        Ran 8 tests in 14.944s

        OK (expected failures=1)
        ```

## General Function Call Workflow

GREP11 can perform encrypt, decrypt, digest, sign and verify operations. For each operation, there are a series of sub-operations or functions.  

For example, the *Encrypt* operation consists of *EncryptInit()*, *Encrypt()*, *EncryptUpdate()*, *EncryptFinal()* and *EncryptSingle()* sub-operations.

#### GREP11 sub-operations for Encrypt:

- *Encrypt***Init()** is used to initialize an operation

- *Encrypt()* is used to encrypt data without the need to perform *EncryptUpdate()* or *EncryptFinal()* sub-operations. *EncryptInit()* must be run prior to the *Encrypt()* call

- *Encrypt***Update()** is used to perform update operations as part of a multi-part operation

- *Encrypt***Final()** is used to perform final operations as part of a multi-part operation

- *Encrypt***Single()** is an IBM EP11 extension to the standard PKCS#11 specification and used to perform a single call without the need to use the **Init**, **Update**, and **Final** sub-operations

The following diagram shows the three calling sequence flows that can be used for *Encrypt*, *Decrypt*, *Digest*, *Sign* and *Verify* operations:

![function work flow](../golang/func_workflow.svg)