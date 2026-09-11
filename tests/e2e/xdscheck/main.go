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

// xdscheck verifies a running dubbod using a managed gateway Pod's credentials.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apache/dubbo-kubernetes/pkg/model"
	core "github.com/dubml/xds-api/core/v1"
	discovery "github.com/dubml/xds-api/service/discovery/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func main() {
	dir := flag.String("credentials", "", "directory containing the gateway Pod Secret data")
	target := flag.String("target", "127.0.0.1:36012", "forwarded secure ADS address")
	serverName := flag.String("server-name", "dubbod.dubbo-system.svc", "TLS server name")
	flag.Parse()
	if err := verify(*dir, *target, *serverName); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify(dir, target, serverName string) error {
	bootstrap, err := os.ReadFile(filepath.Join(dir, "grpc-bootstrap.json"))
	if err != nil {
		return err
	}
	var envelope struct{ Node json.RawMessage }
	if err := json.Unmarshal(bootstrap, &envelope); err != nil {
		return err
	}
	node := &core.Node{}
	if err := protojson.Unmarshal(envelope.Node, node); err != nil {
		return err
	}
	// transit builds a Router node from the shared workload bootstrap.
	parts := strings.Split(node.Id, "~")
	if len(parts) != 4 {
		return fmt.Errorf("unexpected bootstrap node ID format")
	}
	parts[0] = "router"
	node.Id = strings.Join(parts, "~")
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert-chain.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return err
	}
	root, err := os.ReadFile(filepath.Join(dir, "root-cert.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(root) {
		return fmt.Errorf("invalid root bundle")
	}
	for _, delta := range []bool{false, true} {
		for _, scenario := range []string{"valid", "anonymous", "unknown pod", "unknown type"} {
			tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, RootCAs: roots, Certificates: []tls.Certificate{pair}}
			n := proto.Clone(node).(*core.Node)
			typeURL := model.SecretType
			want := codes.OK
			switch scenario {
			case "anonymous":
				tlsConfig.Certificates = nil
				want = codes.Unauthenticated
			case "unknown pod":
				parts := strings.Split(n.Id, "~")
				if len(parts) != 4 {
					return fmt.Errorf("unexpected node ID format")
				}
				parts[2] = "nonexistent.e2e"
				n.Id = strings.Join(parts, "~")
				want = codes.PermissionDenied
			case "unknown type":
				typeURL = "type.googleapis.com/unsupported.Resource"
				want = codes.InvalidArgument
			}
			err := query(target, tlsConfig, n, typeURL, delta)
			if status.Code(err) != want {
				return fmt.Errorf("delta=%v %s: got %v, want %s", delta, scenario, err, want)
			}
			fmt.Printf("PASS delta=%v %s: %s\n", delta, scenario, want)
		}
	}
	return nil
}

func query(target string, tlsConfig *tls.Config, node *core.Node, typeURL string, delta bool) error {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := discovery.NewAggregatedDiscoveryServiceClient(conn)
	if delta {
		stream, err := client.DeltaAggregatedResources(ctx)
		if err != nil {
			return err
		}
		if err := stream.Send(&discovery.DeltaDiscoveryRequest{Node: node, TypeUrl: typeURL, ResourceNamesSubscribe: []string{"default", "ROOTCA"}}); err != nil {
			return err
		}
		res, err := stream.Recv()
		if err != nil {
			return err
		}
		if len(res.Resources) != 2 || res.Nonce == "" {
			return fmt.Errorf("expected two SDS resources and a nonce")
		}
		return stream.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: typeURL, ResponseNonce: res.Nonce})
	}
	stream, err := client.StreamAggregatedResources(ctx)
	if err != nil {
		return err
	}
	if err := stream.Send(&discovery.DiscoveryRequest{Node: node, TypeUrl: typeURL, ResourceNames: []string{"default", "ROOTCA"}}); err != nil {
		return err
	}
	res, err := stream.Recv()
	if err != nil {
		return err
	}
	if len(res.Resources) != 2 || res.Nonce == "" {
		return fmt.Errorf("expected two SDS resources and a nonce")
	}
	return stream.Send(&discovery.DiscoveryRequest{TypeUrl: typeURL, ResourceNames: []string{"default", "ROOTCA"}, ResponseNonce: res.Nonce, VersionInfo: res.VersionInfo})
}
