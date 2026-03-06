// Copyright 2026 The Auth Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Example grpc-propagation demonstrates identity propagation between two gRPC services
// using SignedJWTPropagator with Ed25519-signed JWTs.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/abhipray-cpu/auth"
	authgrpc "github.com/abhipray-cpu/auth/grpc"
	"github.com/abhipray-cpu/auth/propagator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func main() {
	mode := flag.String("mode", "gateway", "gateway or backend")
	flag.Parse()

	switch *mode {
	case "gateway":
		runGateway()
	case "backend":
		runBackend()
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}

func runBackend() {
	// Backend service: decodes propagated identity from incoming metadata.
	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway.example.com",
		Audience: "backend.example.com",
		TTL:      30 * time.Second,
	})
	if err != nil {
		log.Fatalf("failed to create propagator: %v", err)
	}

	server := grpc.NewServer(
		grpc.UnaryInterceptor(authgrpc.UnaryServerInterceptor(authgrpc.ServerConfig{
			Propagator:  prop,
			RequireAuth: true,
		})),
	)

	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Println("Backend service listening on :50052")
	if err := server.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func runGateway() {
	// Gateway service: authenticates users and propagates identity to backend.
	prop, err := propagator.NewSignedJWTPropagator(propagator.SignedJWTConfig{
		Issuer:   "gateway.example.com",
		Audience: "backend.example.com",
		TTL:      30 * time.Second,
	})
	if err != nil {
		log.Fatalf("failed to create propagator: %v", err)
	}

	// Create a connection to the backend with client interceptors.
	conn, err := grpc.NewClient("localhost:50052",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(authgrpc.UnaryClientInterceptor(authgrpc.ClientConfig{
			Propagator: prop,
		})),
	)
	if err != nil {
		log.Fatalf("failed to connect to backend: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Simulate: put an identity in context (normally done by auth middleware).
	identity := &auth.Identity{
		SubjectID:  "user-123",
		AuthMethod: "password",
		AuthTime:   time.Now(),
		SessionID:  "session-abc",
	}
	ctx := auth.SetIdentity(context.Background(), identity)

	// Make a call to the backend — the client interceptor will propagate identity.
	// (In a real app, this would be a typed gRPC call)
	ctx = metadata.AppendToOutgoingContext(ctx, "test", "true")
	_ = conn // In a real app: client.SomeRPC(ctx, req)
	_ = ctx

	fmt.Println("✅ Gateway would propagate identity to backend via SignedJWT")
	fmt.Printf("   User: %s, Method: %s\n", identity.SubjectID, identity.AuthMethod)
}
