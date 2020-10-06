/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package examples

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	grpc "google.golang.org/grpc"
)

// generateECDSAKeyPair generates a 256 bit ECDSA key pair
func generateECDSAKeyPair(cryptoClient pb.CryptoClient) ([]byte, []byte, error) {
	ecParameters, err := asn1.Marshal(util.OIDNamedCurveP256)
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to encode parameter OID: %s", err)
	}
	publicKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_EC_PARAMS, ecParameters),
		util.NewAttribute(ep11.CKA_VERIFY, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	privateKeyECTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_SIGN, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false),
	)
	generateECKeypairRequest := &pb.GenerateKeyPairRequest{
		Mech:            &pb.Mechanism{Mechanism: ep11.CKM_EC_KEY_PAIR_GEN},
		PubKeyTemplate:  publicKeyECTemplate,
		PrivKeyTemplate: privateKeyECTemplate,
	}
	var ecKeypairResponse *pb.GenerateKeyPairResponse
	ecKeypairResponse, err = cryptoClient.GenerateKeyPair(context.Background(), generateECKeypairRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("Generate ECDSA key pair error: %s", err)
	}
	return ecKeypairResponse.PrivKey, ecKeypairResponse.PubKey, nil
}

func createECDSASelfSignedCert(privKey *util.EP11PrivateKey, commonName string, sigAlg x509.SignatureAlgorithm) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(123456789),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: []string{commonName},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privKey.Public(), privKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	return certDERBytes, nil
}

// StartServer starts https server
func CreateServer(listenAddr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("Hello"))
	})
	httpServer := &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}
	return httpServer
}

func newHTTPTestClient(caCertDER []byte) *http.Client {
	x509Cert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		fmt.Printf("x509.ParseCertificate failed: %s\n", err)
		return nil
	}
	clientCertPool := x509.NewCertPool()
	// Append the client certificates from the CA
	clientCertPool.AddCert(x509Cert)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "localhost",
				RootCAs:    clientCertPool,
			},
		},
	}

	return httpClient
}

func ping(client *http.Client, serverAddr string) (string, error) {
	// serverAddr in format of a.b.c.d:port in ipv4 or [::]:port in ipv6
	var serverPort string
	id := strings.LastIndex(serverAddr, ":")
	if id != -1 {
		serverPort = serverAddr[id:]
	} else {
		serverPort = serverAddr
	}
	fullAddr := "https://localhost" + serverPort

	resp, err := client.Get(fullAddr)
	if err != nil {
		return "", fmt.Errorf("Http client get failed: %s", err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("ioutil.ReadAll failed: %s", err)
	}
	return string(data), nil
}

// Example_tls tests TLS communication between a client and server using a certificate and private key that are dynamically generated
func Example_tls() {
	conn, err := grpc.Dial(address, callOpts...)
	if err != nil {
		fmt.Printf("Could not connect to server: %s", err)
		return
	}
	defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)
	privKeyBlob, spki, err := generateECDSAKeyPair(cryptoClient)
	if err != nil {
		fmt.Printf("Failed to generate ECDSA key pair: %s", err)
		return
	}

	// Create signer and raw certificate to build up TLS certificate
	priv, err := util.NewEP11Signer(cryptoClient, privKeyBlob, spki)
	if err != nil {
		fmt.Printf("NewEP11Signer error: %s\n", err)
		return
	}
	certDER, err := createECDSASelfSignedCert(priv, "localhost", x509.ECDSAWithSHA256)
	if err != nil {
		fmt.Printf("createECDSASelfSignedCert error: %s\n", err)
		return
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// Create and start server thread
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.NoClientCert,
	}
	lis, err := tls.Listen("tcp", ":0", tlsCfg)
	if err != nil {
		fmt.Printf("Failed to listen: %s\n", err)
		return
	}
	httpServer := CreateServer(lis.Addr().String())

	defer httpServer.Close()
	go func() {
		httpServer.Serve(lis)
	}()

	// Create TLS client
	client := newHTTPTestClient(certDER)
	strResp, err := ping(client, lis.Addr().String())
	if err != nil {
		fmt.Printf("Ping failed: %s\n", err)
	} else {
		fmt.Printf("Response data from https server: [%s]\n", strResp)
	}

	return

	// Output:
	// Response data from https server: [Hello]
}
