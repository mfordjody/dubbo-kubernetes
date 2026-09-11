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
	"time"

	"github.com/apache/dubbo-kubernetes/pkg/security"
	"github.com/apache/dubbo-kubernetes/pkg/spiffe"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func (s *DiscoveryServer) authenticate(ctx context.Context) ([]string, error) {
	for _, authenticator := range s.Authenticators {
		caller, err := authenticator.Authenticate(security.AuthContext{GrpcContext: ctx})
		if err != nil || caller == nil {
			continue
		}
		var identities []string
		for _, raw := range caller.Identities {
			identity, err := spiffe.ParseIdentity(raw)
			if err == nil && identity.TrustDomain != "" && identity.Namespace != "" && identity.ServiceAccount != "" {
				identities = append(identities, raw)
			}
		}
		if len(identities) > 0 {
			return identities, nil
		}
	}
	return nil, fmt.Errorf("xDS requires an authenticated workload identity")
}

func (s *DiscoveryServer) authorizeConnection(con *Connection) error {
	if con == nil || con.proxy == nil || s.Authorize == nil {
		return status.Error(codes.PermissionDenied, "xDS workload authorization is not configured")
	}
	if !con.authExpiry.IsZero() && !time.Now().Before(con.authExpiry) {
		return status.Error(codes.Unauthenticated, "xDS client certificate has expired; reconnect with renewed credentials")
	}
	if err := s.Authorize(con.proxy, con.ids); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	return nil
}

func certificateExpiry(ctx context.Context) time.Time {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return time.Time{}
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 {
		return time.Time{}
	}
	var expires time.Time
	for _, cert := range info.State.VerifiedChains[0] {
		if expires.IsZero() || cert.NotAfter.Before(expires) {
			expires = cert.NotAfter
		}
	}
	return expires
}
