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

package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/model"
	"github.com/apache/dubbo-kubernetes/pkg/config/constants"
	"github.com/apache/dubbo-kubernetes/pkg/util/sets"
	tlsv1 "github.com/kdubbo/xds-api/extensions/transport_sockets/tls/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testWorkloadSecret(t *testing.T, identity string) (*corev1.Pod, *corev1.Secret) {
	t.Helper()
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "edge", Namespace: "app", UID: "pod-uid"}}
	secret := buildInherentGRPCSecret(pod, nil, nil, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	return pod, secret
}

func TestWorkloadSDSRotationAndIsolation(t *testing.T) {
	pod, secret := testWorkloadSecret(t, "spiffe://cluster.local/ns/app/sa/default")
	g := workloadSecretGenerator{lookup: func(*model.Proxy) (*corev1.Pod, *corev1.Secret) { return pod, secret }}
	proxy := &model.Proxy{Type: model.Router}
	watch := &model.WatchedResource{ResourceNames: sets.New("default", "ROOTCA")}
	first, _, err := g.Generate(proxy, watch, nil)
	if err != nil || len(first) != 2 {
		t.Fatalf("initial SDS = %d, %v", len(first), err)
	}
	var original []byte
	for _, resource := range first {
		decoded := &tlsv1.Secret{}
		if err := resource.Resource.UnmarshalTo(decoded); err != nil {
			t.Fatal(err)
		}
		if resource.Name == "default" {
			original = decoded.GetTlsCertificate().GetCertificateChain().GetInlineBytes()
		}
		if resource.Name == "ROOTCA" && len(decoded.GetValidationContext().GetTrustedCa().GetInlineBytes()) == 0 {
			t.Fatal("missing trust bundle")
		}
	}
	_, secret = testWorkloadSecret(t, "spiffe://cluster.local/ns/app/sa/default")
	rotated, _, err := g.Generate(proxy, watch, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range rotated {
		if resource.Name != "default" {
			continue
		}
		decoded := &tlsv1.Secret{}
		if err := resource.Resource.UnmarshalTo(decoded); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(original, decoded.GetTlsCertificate().GetCertificateChain().GetInlineBytes()) {
			t.Fatal("rotation served old certificate")
		}
	}
	if _, _, err := g.Generate(proxy, &model.WatchedResource{ResourceNames: sets.New("other-secret")}, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign resource accepted: %v", err)
	}
	proxy.Type = model.Inherent
	if _, _, err := g.Generate(proxy, watch, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("application SDS accepted: %v", err)
	}
}

func TestWorkloadSDSRejectsInvalidCredentials(t *testing.T) {
	pod, valid := testWorkloadSecret(t, "spiffe://cluster.local/ns/app/sa/default")
	for _, tc := range []struct {
		name   string
		change func(*corev1.Secret)
	}{
		{"foreign owner", func(s *corev1.Secret) { s.OwnerReferences[0].UID = "another-pod" }},
		{"foreign namespace", func(s *corev1.Secret) { s.Namespace = "other" }},
		{"foreign name", func(s *corev1.Secret) { s.Name = "other-secret" }},
		{"invalid key", func(s *corev1.Secret) { s.Data[constants.KeyFilename] = []byte("invalid") }},
		{"invalid root", func(s *corev1.Secret) { s.Data[constants.CACertNamespaceConfigMapDataName] = []byte("invalid") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := valid.DeepCopy()
			tc.change(s)
			if err := validateWorkloadSecret(pod, s); err == nil {
				t.Fatal("invalid secret accepted")
			}
		})
	}
	_, foreign := testWorkloadSecret(t, "spiffe://cluster.local/ns/app/sa/other")
	if err := validateWorkloadSecret(pod, foreign); err == nil {
		t.Fatal("foreign identity accepted")
	}
	if err := validateWorkloadSecret(pod, nil); err == nil {
		t.Fatal("missing secret accepted")
	}
}
