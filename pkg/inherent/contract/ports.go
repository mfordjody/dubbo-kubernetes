// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

// Package contract defines runtime values shared across Inherent components.
// It must not depend on webhook, controller, or command implementation packages.
package contract

const (
	// GatewayInboundPort is the listener exposed by a managed dxgate workload.
	// Proxyless applications continue to listen on their own declared ports.
	GatewayInboundPort = 25080
)
