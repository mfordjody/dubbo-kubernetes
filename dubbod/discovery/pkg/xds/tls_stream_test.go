//
// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/model"
	v1 "github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/xds/v1"
	"github.com/apache/dubbo-kubernetes/dubbod/security/pkg/server/ca/authenticate"
	"github.com/apache/dubbo-kubernetes/pkg/security"
	discovery "github.com/dubml/xds-api/service/discovery/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestADSAuthenticatesTLSStreams(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	issue := func(identity string, server bool) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			leaf.DNSNames = []string{"dubbod.test"}
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			uri, err := url.Parse(identity)
			if err != nil {
				t.Fatal(err)
			}
			leaf.URIs = []*url.URL{uri}
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: key}
	}
	s, _, _ := newInherentXDSTestServer(t)
	s.Authenticators = []security.Authenticator{&authenticate.ClientCertAuthenticator{}}
	s.Authorize = func(_ *model.Proxy, identities []string) error {
		if len(identities) != 1 || identities[0] != "spiffe://cluster.local/ns/app/sa/default" {
			return fmt.Errorf("workload identity mismatch")
		}
		return nil
	}
	s.serverReady.Store(true)
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{issue("", true)}, ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven})))
	s.Register(server)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	for _, delta := range []bool{false, true} {
		for _, tc := range []struct {
			name, identity string
			want           codes.Code
		}{
			{"valid", "spiffe://cluster.local/ns/app/sa/default", codes.OK},
			{"anonymous", "", codes.Unauthenticated},
			{"other workload", "spiffe://cluster.local/ns/other/sa/default", codes.PermissionDenied},
		} {
			t.Run(fmt.Sprintf("delta=%t/%s", delta, tc.name), func(t *testing.T) {
				cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "dubbod.test"}
				if tc.identity != "" {
					cfg.Certificates = []tls.Certificate{issue(tc.identity, false)}
				}
				conn, err := grpc.NewClient("passthrough:///dubbod.test", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				client := discovery.NewAggregatedDiscoveryServiceClient(conn)
				if delta {
					stream, e := client.DeltaAggregatedResources(ctx)
					err = e
					if err == nil {
						err = stream.Send(&discovery.DeltaDiscoveryRequest{Node: testInherentNode(t), TypeUrl: v1.ListenerType, ResourceNamesSubscribe: []string{testListenerName}})
					}
					if err == nil {
						_, err = stream.Recv()
					}
				} else {
					stream, e := client.StreamAggregatedResources(ctx)
					err = e
					if err == nil {
						err = stream.Send(&discovery.DiscoveryRequest{Node: testInherentNode(t), TypeUrl: v1.ListenerType, ResourceNames: []string{testListenerName}})
					}
					if err == nil {
						_, err = stream.Recv()
					}
				}
				if got := status.Code(err); got != tc.want {
					t.Fatalf("TLS ADS status=%v, want %v: %v", got, tc.want, err)
				}
			})
		}
	}
}

func TestADSExpiredConnectionCannotReceiveResources(t *testing.T) {
	s, con, _ := newInherentXDSTestServer(t)
	con.authExpiry = time.Now().Add(-time.Second)
	if err := s.pushXds(con, nil, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("SotW expiry ignored: %v", err)
	}
	if err := s.pushDeltaXds(con, nil, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Delta expiry ignored: %v", err)
	}
}
