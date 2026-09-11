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
	"fmt"
	"testing"
	"time"

	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/model"
	"github.com/apache/dubbo-kubernetes/pkg/security"
	discovery "github.com/dubml/xds-api/service/discovery/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testAuthenticator struct {
	identities []string
	err        error
}

func (testAuthenticator) AuthenticatorType() string { return "test" }
func (a testAuthenticator) Authenticate(security.AuthContext) (*security.Caller, error) {
	return &security.Caller{Identities: a.identities}, a.err
}

func allowTestWorkload(*model.Proxy, []string) error { return nil }

func TestAuthenticateRequiresWorkloadIdentity(t *testing.T) {
	for _, tc := range []struct {
		name           string
		authenticators []security.Authenticator
		wantOK         bool
	}{
		{name: "unconfigured"},
		{name: "failed", authenticators: []security.Authenticator{testAuthenticator{err: fmt.Errorf("invalid certificate")}}},
		{name: "empty", authenticators: []security.Authenticator{testAuthenticator{}}},
		{name: "dns identity", authenticators: []security.Authenticator{testAuthenticator{identities: []string{"pod.app.svc"}}}},
		{name: "empty service account", authenticators: []security.Authenticator{testAuthenticator{identities: []string{"spiffe://cluster.local/ns/app/sa/"}}}},
		{name: "verified workload", authenticators: []security.Authenticator{testAuthenticator{identities: []string{"spiffe://cluster.local/ns/app/sa/default"}}}, wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &DiscoveryServer{Authenticators: tc.authenticators}
			ids, err := s.authenticate(context.Background())
			if (err == nil) != tc.wantOK || (len(ids) > 0) != tc.wantOK {
				t.Fatalf("authenticate = %v, %v", ids, err)
			}
		})
	}
}

func TestADSRejectsUnauthenticatedStreams(t *testing.T) {
	s, _, stream := newInherentXDSTestServer(t)
	s.Authenticators = nil
	s.serverReady.Store(true)
	if got := status.Code(s.Stream(stream)); got != codes.Unauthenticated {
		t.Fatalf("SotW status = %v", got)
	}
	if got := status.Code(s.StreamDeltas(newFakeDeltaADSStream())); got != codes.Unauthenticated {
		t.Fatalf("Delta status = %v", got)
	}
	if len(s.AllClients()) != 0 {
		t.Fatal("unauthenticated client registered")
	}
}

func TestADSRejectsUnauthorizedWorkload(t *testing.T) {
	for _, delta := range []bool{false, true} {
		t.Run(fmt.Sprintf("delta=%t", delta), func(t *testing.T) {
			s, _, stream := newInherentXDSTestServer(t)
			s.serverReady.Store(true)
			s.Authorize = func(*model.Proxy, []string) error { return fmt.Errorf("wrong service account") }
			done := make(chan error, 1)
			if delta {
				ds := newFakeDeltaADSStream()
				ds.recvCh <- &discovery.DeltaDiscoveryRequest{Node: testInherentNode(t), TypeUrl: "unknown"}
				close(ds.recvCh)
				go func() { done <- s.StreamDeltas(ds) }()
			} else {
				stream.recvCh <- &discovery.DiscoveryRequest{Node: testInherentNode(t), TypeUrl: "unknown"}
				close(stream.recvCh)
				go func() { done <- s.Stream(stream) }()
			}
			select {
			case err := <-done:
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("status = %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("unauthorized stream did not terminate")
			}
			if len(s.AllClients()) != 0 {
				t.Fatal("unauthorized client registered")
			}
		})
	}
}

func TestADSRejectsUnknownResourceWithoutFallback(t *testing.T) {
	s, con, _ := newInherentXDSTestServer(t)
	s.Generators["api"] = staticResourceGenerator{}
	for _, typeURL := range []string{"unknown", "type.googleapis.com/dubbo.v1.HealthInformation"} {
		if err := s.processRequest(&discovery.DiscoveryRequest{TypeUrl: typeURL}, con); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("SotW accepted %s: %v", typeURL, err)
		}
		if err := s.processDeltaRequest(&discovery.DeltaDiscoveryRequest{TypeUrl: typeURL}, con); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("Delta accepted %s: %v", typeURL, err)
		}
	}
}

func TestADSRechecksAuthorizationAfterConnection(t *testing.T) {
	s, con, _ := newInherentXDSTestServer(t)
	s.Authorize = func(*model.Proxy, []string) error { return fmt.Errorf("workload deleted") }
	if err := s.processRequest(&discovery.DiscoveryRequest{TypeUrl: "unknown"}, con); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SotW did not recheck identity: %v", err)
	}
	if err := s.processDeltaRequest(&discovery.DeltaDiscoveryRequest{TypeUrl: "unknown"}, con); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Delta did not recheck identity: %v", err)
	}
	if err := s.pushXds(con, nil, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SotW push did not recheck identity: %v", err)
	}
	if err := s.pushDeltaXds(con, nil, nil); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Delta push did not recheck identity: %v", err)
	}
}

func TestProxyUpdateNotifiesEveryWorkloadConnection(t *testing.T) {
	s, _, _ := newInherentXDSTestServer(t)
	for _, id := range []string{"first", "second", "unrelated"} {
		con := newConnection("10.0.0.1", newFakeADSStream())
		con.proxy = &model.Proxy{Metadata: &model.NodeMetadata{ClusterID: "local"}, IPAddresses: []string{"10.0.0.1"}}
		con.SetID(id)
		con.MarkInitialized()
		if id == "unrelated" {
			con.proxy.Metadata.ClusterID = "other"
		}
		s.addCon(id, con)
	}
	s.ProxyUpdate("local", "10.0.0.1")
	if stats := s.pushQueue.Stats(); stats.Pending != 2 {
		t.Fatalf("queued = %+v, want two connections", stats)
	}
}
