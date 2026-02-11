package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"

	"github.com/kerbos/hurricanex/internal/config"
)

// ServerCredentials creates gRPC transport credentials for the server side
// with mTLS (requiring and verifying client certificates).
func ServerCredentials(cfg config.TLSConfig) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	caCert, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(tlsCfg), nil
}

// ClientCredentials creates gRPC transport credentials for the client side
// with mTLS (presenting client certificate, verifying server certificate).
func ClientCredentials(cfg config.TLSConfig) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caCert, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	return credentials.NewTLS(tlsCfg), nil
}
