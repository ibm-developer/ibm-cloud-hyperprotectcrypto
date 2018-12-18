# Overview

- [Install golang](https://golang.org/doc/install)
- [Change GREP11 server address](https://github.com/vpaprots/ibm-cloud-hyperprotectcrypto/blob/master/golang/examples/main.go#L146)

```
GOPATH/src/github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/examples$ go run main.go
Generated AES Key
Generated IV
Encrypted message
Decrypted message
Hello, this is a very long and creative message without any imagination
GOPATH/src/github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/examples$ 
```

## Things to consider

This example doesn't use TLS. However, this is just standard GRPC client library, TLS documented online elsewheres.

## TODO

- Implementation of mock server still missing.
- Language bindings for other languages