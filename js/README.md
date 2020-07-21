# Overview

1. Make sure to have `node` and `npm` on your machine. The node.js examples were tested with npm version 6.8.0 and node version 8.15.0, running on MacOS.
2. Run `npm install` from the `js` directory.
3. Update the following information in the [examples/client.js](examples/client.js#L15) file.

*NOTE: This information can obtained by logging in to your IBM Cloud account and viewing your Hyper Protect Crypto Serverices (HPCS) instance and IAM information. See the [GREP11 API documentation](https://test.cloud.ibm.com/docs/services/hs-crypto?topic=hs-crypto-grep11-api-ref) for more information about GREP11*.

```
let apiKey = 'API KEY',
    iamEndpoint = 'https://iam.cloud.ibm.com',
    instanceId = 'INSTANCE ID',
    ep11Address = 'GREP11 URL:PORT';
```
4. Run through each example by executing `node examples/<grep11_example>.js`. For example: `node examples/derive-keys.js`. There are nine examples in all, each demonstrating various GREP11 operations:

* `mechanism-info.js`: retrieves information about specified GREP11 mechanism
* `mechanism-list.js`: lists all the mechanisms available in GREP11
* `encrypt-and-decrypt.js`: demonstrates and encrypt and decrypt operations
* `digest-single.js`: demonstrates a single-part digest operation
* `digest-multiple.js`: demonstrates a multi-part digest operation
* `sign-and-verify-ecdsa.js`: demonstrates the sign and verify operations using the ECDSA mechanism
* `sign-and-verify-rsa.js`: demonstrates the sign and verify operations using the RSA mechanism
* `wrap-and-unwrap-key.js`: demonstrates the wrap and unwrap key operations
* `derive-keys.js`: demonstrates the derive key operation

5. Alternatively, you can choose to exercise all the operations at once by updating the following information in the script [start_test.sh](start_test.sh#L17):

```
IAM_API_KEY=<API_KEY>
IAM_ENDPOINT=https://iam.cloud.ibm.com
INSTANCE_ID=<INSTANCE ID>
EP11_ADDRESS=<GREP URL:PORT>
```
Run the script from the `js` directory:
```
./start_test.sh
```
The script produces output similar to the following:
```
=== RUN   Example_getMechanismInfo
MECHANISM INFO: { MinKeySize: '16', MaxKeySize: '32', Flags: '32768' }
=== RUN   Example_encryptAndDecrypt
MESSAGE: Hello, this is a very long and creative message without any imagination
CIPHERTEXT: 523c9d9fb16d53c73cae7d4dba924fe52e5be1da1ed9edf6b1a5d3b4bef60a4b304e33259d0b0798e481c53c39d784845f1a150c1d4fb66b21585b7682b74178f3baee862fe007d6b829b4defacc0999
PLAINTEXT: Hello, this is a very long and creative message without any imagination
=== RUN   Example_digest_single
DATA: This is the data longer than 64 bytes This is the data longer than 64 bytes
DIGEST: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
=== RUN   Example_digest_multiple
DATA: This is the data longer than 64 bytes This is the data longer than 64 bytes
DIGEST: ad4e0b6e309d192862ec6db692d17072ddd3a98ccd37afe642a04f7ca554c94c
=== RUN   Example_signAndVerifyUsingRSAKeyPair
DATA: 9fa6c619db022915ff788599c81c27ac5a349834146cfc5034e7353ed5d92727
VERIFIED SIGNATURE: 294002b6a45517eafea6fe39c6153ceb0f68d28dbae1d12f38ead688ac7a7940c7ea126528effe894329b418d12cf6526a9016860e5026824f0816a4a46716d62de158a9ee6db6d4500e24c1fec6a73b76aec6a1e6996fc872ecc80034b8557f56ed400910c2ae5cfad0a0b4501ceca40a820fef9d4c09d645dce16af0aca1d20fc3204fc19a9d3a89676f2c6ff38f40dd630a74165fa45847bde3bd42143ca451c9be4ea8be6f7aaa1f4ff45bbe28c490f6988aa8b976e736c3232a8c82641af5f497f294115f1987e5808ca8959305385c2cafe356852fe386ad6d92a20523419d4e7e4f538789fa706e51df2a12dbac907a64ad955888cd6309ab7a282d8c
=== RUN   Example_signAndVerifyUsingECDSAKeyPair
DATA: 9fa6c619db022915ff788599c81c27ac5a349834146cfc5034e7353ed5d92727
VERIFIED SIGNATURE: 29b21cf04691745f49dbae01fea60478ffa79721960770ba5d9dab1b8907367049915277797fd2b9cd70238bf6f39bf4512260f4f5cd9408d9a0d719fd2457d7
=== RUN   Example_wrapAndUnwrapKey
AES KEY: 00000000000000000000000000000000000000000000000000000000000000004e49482330802e9cf5c80fd81c58c2570000000000008d25000000000000000112349e3111b5d32451ff269ad859d42fed64744ab566be30d24adc00f449b023166f92bc94e4515afac775e24edeba2b81ca58dd063bdea3eecbba9ed5ba25833b2900874849acba560cd287a66fa5567297a0494640265a0d4cac93cb8e15144e1b89ff2694349524e092f629c201cc0d5f98813bdaf0dd2f7cfb350af0898c7d66a95ae20d5ced19ee43aacab21bf61a6ccf4021b4addb78fd3429347929a3fdb21c0aeffe8e71b1c45dbad89cf8da1421ca8dbab1b41d950f183726362d2a
WRAPPED: a020b5c4ca895f3e79f1d453b1783b401ea2631e43c8f44620a14b0d1cd1af842f3f19a183ee82d593813f56e1c611929b6ea473cb6b94ac305536665fcf558b138baef80830636d41b72cda6bd711fe5cb7efe7401bfc6f5ba08c49a59a062e0e3519cbed30c7bea51d8991d01f7e8db64a78d461d433e86944e63e4c2508f125fe937939c21c8eb50b00582ac13ecceafaf5c6f6e135e2817c837df79d3f5192812151e546951a59763afec924accbce89db2a0c7567ffad76f24a489afbad1ebdef878a230b7330ddc06fb4761142a0becb9c20158e83fe95e9819016a66482ddf478b3f33a0f8b06c9811a5e20a1d2ac187ea6c3fad8c1fc15e3fc927abd
CHECKSUM: 432a1700000080
UNWRAPPED KEY: 00000000000000000000000000000000000000000000000000000000000000004e49482330802e9cf5c80fd81c58c2570000000000000c01000000000000000112344b7cf33d8917ffbf0fe357e5955d841e900e29a52271b51c834cc89f17fc2b5e9af8b4c019b4b416272fb7d4d48d59118e4b098e971d8204e7cb3e35b5058461ea5450cab45bcca4954dc6dd61237f9eb3350b0f84a22eddbac89ba44b774fe380ebf90d85e3c27ba073881194ca26041008e1180c9595924b0aa42031a4cb35f31591ff363879d42d3edbc04034c4d4a878c319232d7b62eb02a7ac721ccaf3e35e730b1aa25f2c52fe98257396216cc24db55bb255f027ae0a0e65d9696e946c01fbce1a4aa4703ba332927f14
=== RUN   Example_deriveKey
MESSAGE: Hello World!
CIPHERTEXT: bb0a5699069452ee40f5d4835e75572a
PLAINTEXT: Hello World!
```


