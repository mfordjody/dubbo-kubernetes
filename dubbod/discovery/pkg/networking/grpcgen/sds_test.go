// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package grpcgen

import (
	"testing"

	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/model"
	"github.com/apache/dubbo-kubernetes/pkg/cluster"
	"github.com/apache/dubbo-kubernetes/pkg/config/constants"
	"github.com/apache/dubbo-kubernetes/pkg/kube/inject"
	"github.com/apache/dubbo-kubernetes/pkg/security"
	"github.com/apache/dubbo-kubernetes/pkg/util/sets"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	tlsv1 "github.com/kdubbo/xds-api/extensions/transport_sockets/tls/v1"
)

func TestSecretGeneratorServesOnlyRouterWorkloadCertificate(t *testing.T) {
	const (
		namespace = "dubbo-system"
		podName   = "dxgate-abc"
	)
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespace},
		Spec:       corev1.PodSpec{ServiceAccountName: "dxgate"},
	}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      inject.InherentGRPCSecretName(podName),
			Namespace: namespace,
		},
		Data: map[string][]byte{
			constants.CertChainFilename:                []byte("cert"),
			constants.KeyFilename:                      []byte("key"),
			constants.CACertNamespaceConfigMapDataName: []byte("root"),
		},
	})
	generator := NewSecretGenerator(client)
	proxy := &model.Proxy{
		Type: model.Router,
		ID:   podName + "." + namespace,
		Metadata: &model.NodeMetadata{
			Generator: "grpc",
			ClusterID: cluster.ID("Kubernetes"),
			Namespace: namespace,
		},
		AuthenticatedIdentities: []string{"spiffe://cluster.local/ns/dubbo-system/sa/dxgate"},
	}
	watch := &model.WatchedResource{
		ResourceNames: sets.New(security.WorkloadKeyCertResourceName, security.RootCertReqResourceName),
	}

	resources, _, err := generator.Generate(proxy, watch, nil)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("len(resources) = %d, want 2", len(resources))
	}
	seen := map[string]*tlsv1.Secret{}
	for _, resource := range resources {
		secret := &tlsv1.Secret{}
		if err := resource.Resource.UnmarshalTo(secret); err != nil {
			t.Fatalf("unmarshal %q: %v", resource.Name, err)
		}
		seen[resource.Name] = secret
	}
	if got := seen[security.WorkloadKeyCertResourceName].GetTlsCertificate().GetCertificateChain().GetInlineBytes(); string(got) != "cert" {
		t.Fatalf("certificate = %q, want cert", got)
	}
	if got := seen[security.RootCertReqResourceName].GetValidationContext().GetTrustedCa().GetInlineBytes(); string(got) != "root" {
		t.Fatalf("root = %q, want root", got)
	}
}

func TestSecretGeneratorRejectsUnauthorizedResource(t *testing.T) {
	const (
		namespace = "dubbo-system"
		podName   = "dxgate-abc"
	)
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespace},
		Spec:       corev1.PodSpec{ServiceAccountName: "dxgate"},
	}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: inject.InherentGRPCSecretName(podName), Namespace: namespace},
		Data: map[string][]byte{
			constants.CertChainFilename:                []byte("cert"),
			constants.KeyFilename:                      []byte("key"),
			constants.CACertNamespaceConfigMapDataName: []byte("root"),
		},
	})
	_, _, err := NewSecretGenerator(client).Generate(&model.Proxy{
		Type:                    model.Router,
		ID:                      podName + "." + namespace,
		Metadata:                &model.NodeMetadata{Namespace: namespace},
		AuthenticatedIdentities: []string{"spiffe://cluster.local/ns/dubbo-system/sa/dxgate"},
	}, &model.WatchedResource{ResourceNames: sets.New("other-secret")}, nil)
	if err == nil {
		t.Fatal("Generate() error = nil, want unauthorized resource error")
	}
}
