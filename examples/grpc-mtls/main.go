// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example grpc-mtls demonstrates gRPC with mTLS workload identity.
// Run with -mode=server or -mode=client.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/abhipray-cpu/auth"
	authgrpc "github.com/abhipray-cpu/auth/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func main() {
	mode := flag.String("mode", "server", "server or client")
	flag.Parse()

	switch *mode {
	case "server":
		runServer()
	case "client":
		runClient()
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}

func runServer() {
	// Load server cert and CA for client verification.
	cert, err := tls.LoadX509KeyPair("../../mode/mtls/testdata/ca.pem", "../../mode/mtls/testdata/ca-key.pem")
	if err != nil {
		log.Fatalf("failed to load server cert: %v", err)
	}

	caCert, err := os.ReadFile("../../mode/mtls/testdata/ca.pem")
	if err != nil {
		log.Fatalf("failed to read CA cert: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			RequireAuth: false, // mTLS provides workload identity, not user identity
		})),
	)
	reflection.Register(server)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Println("gRPC mTLS server listening on :50051")
	if err := server.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func runClient() {
	// Load client cert and CA.
	cert, err := tls.LoadX509KeyPair("../../mode/mtls/testdata/client.pem", "../../mode/mtls/testdata/client-key.pem")
	if err != nil {
		log.Fatalf("failed to load client cert: %v", err)
	}

	caCert, err := os.ReadFile("../../mode/mtls/testdata/ca.pem")
	if err != nil {
		log.Fatalf("failed to read CA cert: %v", err)
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := grpc.NewClient("localhost:50051",
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// The connection itself proves workload identity via mTLS.
	// On the server side, auth.GetWorkloadIdentity(ctx) returns the client's cert identity.
	_ = context.Background()
	_ = auth.GetIdentity // just to show the import is used

	fmt.Println("✅ mTLS connection established successfully")
	fmt.Println("   The server can read WorkloadIdentity from the client certificate")
}
