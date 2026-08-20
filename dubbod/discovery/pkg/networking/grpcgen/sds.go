// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package grpcgen

import (
	"context"
	"fmt"
	"strings"

	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/model"
	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/util/protoconv"
	"github.com/apache/dubbo-kubernetes/pkg/config/constants"
	"github.com/apache/dubbo-kubernetes/pkg/kube/inject"
	"github.com/apache/dubbo-kubernetes/pkg/security"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	core "github.com/kdubbo/xds-api/core/v1"
	tlsv1 "github.com/kdubbo/xds-api/extensions/transport_sockets/tls/v1"
	discovery "github.com/kdubbo/xds-api/service/discovery/v1"
)

// SecretGenerator exposes only the certificate already issued for the
// authenticated dxgate Pod represented by the xDS node. It never serves an
// arbitrary Kubernetes Secret name supplied by the client.
type SecretGenerator struct {
	client kubernetes.Interface
}

func NewSecretGenerator(client kubernetes.Interface) *SecretGenerator {
	return &SecretGenerator{client: client}
}

func (g *SecretGenerator) Generate(proxy *model.Proxy, w *model.WatchedResource, _ *model.PushRequest) (model.Resources, model.XdsLogDetails, error) {
	if proxy == nil || proxy.Type != model.Router || w == nil || g.client == nil {
		return nil, model.DefaultXdsLogDetails, nil
	}
	namespace := model.GetProxyConfigNamespace(proxy)
	podName, ok := routerPodName(proxy.ID, namespace)
	if !ok {
		return nil, model.DefaultXdsLogDetails, fmt.Errorf("invalid dxgate node identity %q", proxy.ID)
	}
	secret, err := g.client.CoreV1().Secrets(namespace).Get(
		context.Background(),
		inject.InherentGRPCSecretName(podName),
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, model.DefaultXdsLogDetails, fmt.Errorf("read SDS material for %s/%s: %w", namespace, podName, err)
	}
	pod, err := g.client.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, model.DefaultXdsLogDetails, fmt.Errorf("read dxgate identity for %s/%s: %w", namespace, podName, err)
	}
	serviceAccount := pod.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	if !authorizedWorkloadIdentity(proxy.AuthenticatedIdentities, namespace, serviceAccount) {
		return nil, model.DefaultXdsLogDetails, fmt.Errorf("SDS requires the verified identity for %s/%s", namespace, serviceAccount)
	}

	requested := w.ResourceNames
	if requested == nil || len(requested) == 0 {
		return nil, model.DefaultXdsLogDetails, nil
	}
	resources := make(model.Resources, 0, len(requested))
	for name := range requested {
		var xdsSecret *tlsv1.Secret
		switch name {
		case security.WorkloadKeyCertResourceName:
			certChain := secret.Data[constants.CertChainFilename]
			privateKey := secret.Data[constants.KeyFilename]
			if len(certChain) == 0 || len(privateKey) == 0 {
				return nil, model.DefaultXdsLogDetails, fmt.Errorf("SDS material for %s/%s is missing certificate or private key", namespace, podName)
			}
			xdsSecret = &tlsv1.Secret{
				Name: name,
				Type: &tlsv1.Secret_TlsCertificate{TlsCertificate: &tlsv1.TlsCertificate{
					CertificateChain: inlineSDSBytes(certChain),
					PrivateKey:       inlineSDSBytes(privateKey),
				}},
			}
		case security.RootCertReqResourceName:
			root := secret.Data[constants.CACertNamespaceConfigMapDataName]
			if len(root) == 0 {
				return nil, model.DefaultXdsLogDetails, fmt.Errorf("SDS material for %s/%s is missing root certificate", namespace, podName)
			}
			xdsSecret = &tlsv1.Secret{
				Name: name,
				Type: &tlsv1.Secret_ValidationContext{ValidationContext: &tlsv1.CertificateValidationContext{
					TrustedCa: inlineSDSBytes(root),
				}},
			}
		default:
			return nil, model.DefaultXdsLogDetails, fmt.Errorf("SDS resource %q is not authorized for dxgate node %q", name, proxy.ID)
		}
		resources = append(resources, &discovery.Resource{Name: name, Resource: protoconv.MessageToAny(xdsSecret)})
	}
	return resources, model.DefaultXdsLogDetails, nil
}

func routerPodName(nodeID, namespace string) (string, bool) {
	if namespace == "" {
		return "", false
	}
	suffix := "." + namespace
	if !strings.HasSuffix(nodeID, suffix) {
		return "", false
	}
	name := strings.TrimSuffix(nodeID, suffix)
	return name, name != ""
}

func inlineSDSBytes(data []byte) *core.DataSource {
	return &core.DataSource{Specifier: &core.DataSource_InlineBytes{InlineBytes: data}}
}

func authorizedWorkloadIdentity(identities []string, namespace, serviceAccount string) bool {
	suffix := "/ns/" + namespace + "/sa/" + serviceAccount
	for _, identity := range identities {
		if strings.HasPrefix(identity, "spiffe://") && strings.HasSuffix(identity, suffix) {
			return true
		}
	}
	return false
}
