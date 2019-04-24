# Overview

The module implements an openssl engine plugin by calling `ep11server` service. It can be used to generate ECDSA key pairs and to generate ECDSA certificate request and certificate.

## Quick start under Macbook/Linux

1. Install [openssl-1.0.2r](https://www.openssl.org/source/). If there are mutiple version of openssl existing in system, make sure to update `PATH` and/or `LD_LIBRARY_PATH` so that the cgo can find correct openssl excutable binary and/or library. 
2. [Install Golang](https://golang.org/doc/install)
3. When necessary, update openssl include folder for [Macbook](openssleng_ep11.go#L11) or [Linux](openssleng_ep11.go#L12) and update library folder for [Macbook](openssleng_ep11.go#L15) or [Linux](openssleng_ep11.go#L16).
4. [Change ep11server address](openssleng_ep11.go#L39)
5. Under folder `openssl-eng`, type `make`. Shared library `grep11_eng.so` will be created.
6. In the same directory, type the following commands to create ca and server certificates and perform TLS connection test between client and server:

	```Bash
	#Create EC parameter file for 256 bits prime curve
	openssl ecparam -name prime256v1 -out prime256v1-para.pem
	
	#Create ECDSA key pairs and self-signed certificate
	openssl req -engine `pwd`/grep11_eng.so -x509 -sha256 -nodes -days 3650 -subj '/CN=This is CA/' -newkey EC:prime256v1-para.pem -keyout ca-prikey-prime256v1-my.pem -out ca-cert-prime256v1.pem

	#Create server private key and certificate request
	openssl req -engine `pwd`/grep11_eng.so -new -sha256 -nodes -subj '/CN=localhost/' -newkey EC:prime256v1-para.pem  -keyout server-prikey-prime256v1-my.pem -out server-prime256v1.csr
	
	#Create server certificate signed by CA certificate
	openssl x509 -engine `pwd`/grep11_eng.so -req -sha256 -days 3650 -set_serial 12345 -in server-prime256v1.csr -CA ca-cert-prime256v1.pem -CAkey ca-prikey-prime256v1-my.pem -out server-cert-prime256v1.pem

	#Start Server
	openssl s_server -engine `pwd`/grep11_eng.so -keyform engine  -key server-prikey-prime256v1-my.pem -cert server-cert-prime256v1.pem -www -accept 1553 &
	
	sleep 1

	#Start Client
	openssl s_client -tls1_2 -CApath . -CAfile ca-cert-prime256v1.pem -connect 127.0.0.1:1553 <<< "GET /"
	```
