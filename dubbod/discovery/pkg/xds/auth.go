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

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func (s *DiscoveryServer) authenticate(ctx context.Context) ([]string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, nil
	}
	if len(tlsInfo.State.VerifiedChains) == 0 {
		return nil, fmt.Errorf("xDS client certificate was not verified")
	}
	leaf := tlsInfo.State.VerifiedChains[0][0]
	identities := make([]string, 0, len(leaf.URIs))
	for _, uri := range leaf.URIs {
		if uri != nil {
			identities = append(identities, uri.String())
		}
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("xDS client certificate has no URI SAN identity")
	}
	return identities, nil
}
