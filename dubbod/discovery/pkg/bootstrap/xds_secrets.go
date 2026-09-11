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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/model"
	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/util/protoconv"
	"github.com/apache/dubbo-kubernetes/pkg/config/constants"
	"github.com/apache/dubbo-kubernetes/pkg/kube/inject"
	"github.com/apache/dubbo-kubernetes/pkg/security"
	"github.com/apache/dubbo-kubernetes/pkg/spiffe"
	"github.com/apache/dubbo-kubernetes/pkg/util/sets"
	core "github.com/dubml/xds-api/core/v1"
	tlsv1 "github.com/dubml/xds-api/extensions/transport_sockets/tls/v1"
	discovery "github.com/dubml/xds-api/service/discovery/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
)

type workloadSecretGenerator struct {
	lookup func(*model.Proxy) (*corev1.Pod, *corev1.Secret)
}

func (s *Server) lookupXDSWorkloadSecret(proxy *model.Proxy) (*corev1.Pod, *corev1.Secret) {
	controller := s.xdsWorkloadController(proxy)
	if controller == nil {
		return nil, nil
	}
	pod := controller.pods.Get(strings.TrimSuffix(proxy.ID, "."+proxy.Metadata.Namespace), proxy.Metadata.Namespace)
	if pod == nil {
		return nil, nil
	}
	return pod, controller.secrets.Get(inject.InherentGRPCSecretNameForMeta(pod.ObjectMeta), pod.Namespace)
}

func (g workloadSecretGenerator) Generate(proxy *model.Proxy, w *model.WatchedResource, _ *model.PushRequest) (model.Resources, model.XdsLogDetails, error) {
	if proxy == nil || !proxy.IsRouter() {
		return nil, model.DefaultXdsLogDetails, status.Error(codes.PermissionDenied, "SDS is only available to managed gateways")
	}
	names := sets.New("default", security.RootCertReqResourceName)
	if w != nil && len(w.ResourceNames) > 0 {
		names = w.ResourceNames
	}
	for name := range names {
		if name != "default" && name != security.RootCertReqResourceName {
			return nil, model.DefaultXdsLogDetails, status.Errorf(codes.PermissionDenied, "SDS resource %q is not a workload credential", name)
		}
	}
	pod, secret := g.lookup(proxy)
	if err := validateWorkloadSecret(pod, secret); err != nil {
		return nil, model.DefaultXdsLogDetails, status.Error(codes.FailedPrecondition, err.Error())
	}
	resources := make(model.Resources, 0, len(names))
	for _, name := range sets.SortedList(names) {
		resource := &tlsv1.Secret{Name: name}
		if name == security.RootCertReqResourceName {
			resource.Type = &tlsv1.Secret_ValidationContext{ValidationContext: &tlsv1.CertificateValidationContext{TrustedCa: secretBytes(secret.Data[constants.CACertNamespaceConfigMapDataName])}}
		} else {
			resource.Type = &tlsv1.Secret_TlsCertificate{TlsCertificate: &tlsv1.TlsCertificate{CertificateChain: secretBytes(secret.Data[constants.CertChainFilename]), PrivateKey: secretBytes(secret.Data[constants.KeyFilename])}}
		}
		resources = append(resources, &discovery.Resource{Name: name, Resource: protoconv.MessageToAny(resource)})
	}
	return resources, model.DefaultXdsLogDetails, nil
}

func secretBytes(value []byte) *core.DataSource {
	return &core.DataSource{Specifier: &core.DataSource_InlineBytes{InlineBytes: append([]byte(nil), value...)}}
}

func validateWorkloadSecret(pod *corev1.Pod, secret *corev1.Secret) error {
	if pod == nil || secret == nil || pod.DeletionTimestamp != nil {
		return fmt.Errorf("workload credentials are not available")
	}
	owned := false
	for _, owner := range secret.OwnerReferences {
		if owner.APIVersion == "v1" && owner.Kind == "Pod" && owner.Name == pod.Name && owner.UID == pod.UID && pod.UID != "" {
			owned = true
		}
	}
	if !owned || secret.Namespace != pod.Namespace || secret.Name != inject.InherentGRPCSecretNameForMeta(pod.ObjectMeta) {
		return fmt.Errorf("workload credentials do not belong to the requesting Pod")
	}
	pair, err := tls.X509KeyPair(secret.Data[constants.CertChainFilename], secret.Data[constants.KeyFilename])
	if err != nil {
		return fmt.Errorf("invalid workload certificate/key pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 {
		return fmt.Errorf("invalid workload certificate identity")
	}
	identity, err := spiffe.ParseIdentity(leaf.URIs[0].String())
	sa := pod.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	if err != nil || identity.Namespace != pod.Namespace || identity.ServiceAccount != sa {
		return fmt.Errorf("workload certificate does not match Pod identity")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(secret.Data[constants.CACertNamespaceConfigMapDataName]) {
		return fmt.Errorf("invalid workload trust bundle")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("invalid workload intermediate certificate")
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("workload certificate is not valid against its trust bundle")
	}
	return nil
}
