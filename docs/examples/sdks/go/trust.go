package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	hush "github.com/backbay-labs/hush/packages/go/hushspec"
)

func checkTrust(policyPath string, resolved *hush.HushSpec) {
	// Test material generated in memory, never a production signing identity.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	must(err)
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	must(err)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	ring, err := hush.KeyringFromPublicKey(publicPEM, "docs")
	must(err)
	envelope, err := hush.SignPolicy(resolved, privatePEM, hush.SignOptions{})
	must(err)
	require(hush.VerifyPolicy(resolved, envelope, hush.VerifyOptions{Keyring: ring}).OK, "signature failed")
	other, _, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	otherDER, err := x509.MarshalPKIXPublicKey(other)
	must(err)
	wrong, err := hush.KeyringFromPublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherDER}), "wrong")
	must(err)
	require(!hush.VerifyPolicy(resolved, envelope, hush.VerifyOptions{Keyring: wrong}).OK, "wrong key accepted")
	provider := hush.NewFileProvider(policyPath, hush.ResolveOptions{})
	guard, err := hush.NewGuardFromProvider(provider, hush.GuardOptions{})
	must(err)
	outcome, err := guard.Check(context.Background(), &hush.EvaluationAction{Type: "tool_call", Target: "deploy"})
	must(err)
	require(!outcome.Allowed(), "provider guard allowed deploy")
}
