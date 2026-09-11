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

package model

import (
	"cmp"
	"strings"
	"sync"
	"time"

	"github.com/apache/dubbo-kubernetes/pkg/config/schema/gvk"
	networking "github.com/kdubbo/api/networking/v1alpha3"
	sigsk8siogatewayapiapisv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apache/dubbo-kubernetes/dubbod/discovery/pkg/serviceregistry/provider"
	"github.com/apache/dubbo-kubernetes/pkg/config"
	"github.com/apache/dubbo-kubernetes/pkg/config/host"
	"github.com/apache/dubbo-kubernetes/pkg/config/schema/kind"
	"github.com/apache/dubbo-kubernetes/pkg/config/visibility"
	"github.com/apache/dubbo-kubernetes/pkg/slices"
	"github.com/apache/dubbo-kubernetes/pkg/spiffe"
	"github.com/apache/dubbo-kubernetes/pkg/util/sets"
	meshv1alpha1 "github.com/kdubbo/api/mesh/v1alpha1"
	"go.uber.org/atomic"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// ConfigSnapshot contains service and policy state shared by application and xDS configuration.
// It owns no subscriptions, wire versions, acknowledgements, or connection status.
type ConfigSnapshot struct {
	Mesh            *meshv1alpha1.MeshConfig `json:"-"`
	initializeMutex sync.Mutex
	InitDone        atomic.Bool
	// GatewayAPIController holds a reference to the Gateway API controller.
	// When enabled, this controller is responsible for translating Kubernetes
	// Gateway API resources into internal Dubbo resources during push.
	GatewayAPIController   GatewayController
	clusterLocalHosts      ClusterLocalHosts
	exportToDefaults       exportToDefaults
	ServiceIndex           serviceIndex
	httpRouteIndex         httpRouteIndex
	dxgateServiceIndex     dxgateServiceIndex
	backendTLSPolicyIndex  backendTLSPolicyIndex
	faultInjectionIndex    faultInjectionPolicyIndex
	serviceActivationIndex serviceActivationPolicyIndex
	serviceAccounts        map[serviceAccountKey][]string
	AuthenticationPolicies *AuthenticationPolicies
}

type serviceAccountKey struct {
	hostname  host.Name
	namespace string
}

type serviceIndex struct {
	privateByNamespace   map[string][]*Service
	public               []*Service
	exportedToNamespace  map[string][]*Service
	HostnameAndNamespace map[host.Name]map[string]*Service `json:"-"`
	instancesByPort      map[string]map[int][]*DubboEndpoint
}

type exportToDefaults struct {
	service sets.Set[visibility.Instance]
}

type httpRouteIndex struct {
	// hostToRoutes keeps the Gateway API HTTPRoutes keyed by hostname
	hostToRoutes map[host.Name][]config.Config
}

type dxgateServiceIndex struct {
	byNamespace map[string]map[string]config.Config
}

type backendTLSPolicyIndex struct {
	serviceTLS map[string]BackendTLSSettings
}

type BackendTLSSettings struct {
	SNI string
}

const ActivationGatewayServiceName = "dxgate-gateway"

type serviceActivationPolicyIndex struct {
	services map[string][]string
}

func NewConfigSnapshot() *ConfigSnapshot {
	return &ConfigSnapshot{
		ServiceIndex:          newServiceIndex(),
		dxgateServiceIndex:    dxgateServiceIndex{byNamespace: map[string]map[string]config.Config{}},
		backendTLSPolicyIndex: backendTLSPolicyIndex{serviceTLS: map[string]BackendTLSSettings{}},
		serviceActivationIndex: serviceActivationPolicyIndex{
			services: map[string][]string{},
		},
		serviceAccounts: map[serviceAccountKey][]string{},
	}
}

func newServiceIndex() serviceIndex {
	return serviceIndex{
		public:               []*Service{},
		privateByNamespace:   map[string][]*Service{},
		exportedToNamespace:  map[string][]*Service{},
		HostnameAndNamespace: map[host.Name]map[string]*Service{},
		instancesByPort:      map[string]map[int][]*DubboEndpoint{},
	}
}

func (ps *ConfigSnapshot) initDefaultExportMaps() {
	ps.exportToDefaults.service = sets.New[visibility.Instance]()
	if ps.Mesh.DefaultServiceExportTo != nil {
		for _, e := range ps.Mesh.DefaultServiceExportTo {
			ps.exportToDefaults.service.Insert(visibility.Instance(e))
		}
	} else {
		ps.exportToDefaults.service.Insert(visibility.Public)
	}

}

func (ps *ConfigSnapshot) Initialize(env *Environment, oldSnapshot *ConfigSnapshot, change *ConfigChange) {
	ps.initializeMutex.Lock()
	defer ps.initializeMutex.Unlock()
	if ps.InitDone.Load() {
		return
	}

	ps.Mesh = env.Mesh()

	ps.initDefaultExportMaps()

	if change == nil || oldSnapshot == nil || !oldSnapshot.InitDone.Load() || change.Forced {
		ps.createNewContext(env)
		ps.applyServiceActivationPolicyUpdates(change)
	} else {
		ps.updateContext(env, oldSnapshot, change)
	}

	ps.clusterLocalHosts = env.ClusterLocal().GetClusterLocalHosts()

	ps.InitDone.Store(true)
}

func SortServicesByCreationTime(services []*Service) []*Service {
	slices.SortStableFunc(services, func(i, j *Service) int {
		if r := i.CreationTime.Compare(j.CreationTime); r != 0 {
			return r
		}
		if r := cmp.Compare(i.Attributes.Name, j.Attributes.Name); r != 0 {
			return r
		}
		return cmp.Compare(i.Attributes.Namespace, j.Attributes.Namespace)
	})
	return services
}

func resolveServiceAliases(allServices []*Service, configsUpdated sets.Set[ConfigKey]) {
	rawAlias := map[NamespacedHostname]host.Name{}
	for _, s := range allServices {
		if s.Resolution != Alias {
			continue
		}
		nh := NamespacedHostname{
			Hostname:  s.Hostname,
			Namespace: s.Attributes.Namespace,
		}
		rawAlias[nh] = host.Name(s.Attributes.ExternalName)
	}

	unnamespacedRawAlias := make(map[host.Name]host.Name, len(rawAlias))
	for k, v := range rawAlias {
		unnamespacedRawAlias[k.Hostname] = v
	}

	resolvedAliases := make(map[NamespacedHostname]host.Name, len(rawAlias))
	for alias, referencedService := range rawAlias {
		if _, f := unnamespacedRawAlias[referencedService]; !f {
			// Common case: alias pointing to a concrete service
			resolvedAliases[alias] = referencedService
			continue
		}
		seen := sets.New(alias.Hostname, referencedService)
		for {
			n, f := unnamespacedRawAlias[referencedService]
			if !f {
				resolvedAliases[alias] = referencedService
				break
			}
			if seen.InsertContains(n) {
				break
			}
			referencedService = n
		}
	}

	aliasesForService := map[host.Name][]NamespacedHostname{}
	for alias, concrete := range resolvedAliases {
		aliasesForService[concrete] = append(aliasesForService[concrete], alias)

		aliasKey := ConfigKey{
			// Kind:      kind.ServiceEntry,
			// Name:      alias.Hostname.String(),
			// Namespace: alias.Namespace,
		}
		if configsUpdated.Contains(aliasKey) {
			for _, svc := range allServices {
				if svc.Hostname == concrete {
					configsUpdated.Insert(ConfigKey{
						// Kind:      kind.ServiceEntry,
						// Name:      concrete.String(),
						// Namespace: svc.Attributes.Namespace,
					})
				}
			}
		}
	}
	for _, v := range aliasesForService {
		slices.SortFunc(v, func(a, b NamespacedHostname) int {
			if r := cmp.Compare(a.Namespace, b.Namespace); r != 0 {
				return r
			}
			return cmp.Compare(a.Hostname, b.Hostname)
		})
	}

	for i, s := range allServices {
		if aliases, f := aliasesForService[s.Hostname]; f {
			// This service has an alias; set it. We need to make a copy since the underlying Service is shared
			s = s.DeepCopy()
			s.Attributes.Aliases = aliases
			allServices[i] = s
		}
	}
}

func (ps *ConfigSnapshot) initServiceRegistry(env *Environment, configsUpdate sets.Set[ConfigKey]) {
	allServices := SortServicesByCreationTime(env.Services())
	resolveServiceAliases(allServices, configsUpdate)

	for _, s := range allServices {
		portMap := map[string]int{}
		ports := sets.New[int]()
		for _, port := range s.Ports {
			portMap[port.Name] = port.Port
			ports.Insert(port.Port)
		}

		svcKey := s.Key()
		if _, ok := ps.ServiceIndex.instancesByPort[svcKey]; !ok {
			ps.ServiceIndex.instancesByPort[svcKey] = make(map[int][]*DubboEndpoint)
		}
		shards, ok := env.EndpointIndex.ShardsForService(string(s.Hostname), s.Attributes.Namespace)
		if ok {
			instancesByPort := shards.CopyEndpoints(portMap, ports)
			// Iterate over the instances and add them to the service index to avoid overriding the existing port instances.
			for port, instances := range instancesByPort {
				ps.ServiceIndex.instancesByPort[svcKey][port] = instances
			}
		}
		if _, f := ps.ServiceIndex.HostnameAndNamespace[s.Hostname]; !f {
			ps.ServiceIndex.HostnameAndNamespace[s.Hostname] = map[string]*Service{}
		}
		if existing := ps.ServiceIndex.HostnameAndNamespace[s.Hostname][s.Attributes.Namespace]; existing != nil &&
			(existing.Attributes.ServiceRegistry == provider.Kubernetes || s.Attributes.ServiceRegistry != provider.Kubernetes) {
			log.Debugf("Service %s/%s from registry %s ignored by %s/%s/%s", s.Attributes.Namespace, s.Hostname, s.Attributes.ServiceRegistry,
				existing.Attributes.ServiceRegistry, existing.Attributes.Namespace, existing.Hostname)
		} else {
			ps.ServiceIndex.HostnameAndNamespace[s.Hostname][s.Attributes.Namespace] = s
		}

		ns := s.Attributes.Namespace
		if s.Attributes.ExportTo.IsEmpty() {
			if ps.exportToDefaults.service.Contains(visibility.Private) {
				ps.ServiceIndex.privateByNamespace[ns] = append(ps.ServiceIndex.privateByNamespace[ns], s)
			} else if ps.exportToDefaults.service.Contains(visibility.Public) {
				ps.ServiceIndex.public = append(ps.ServiceIndex.public, s)
			}
		} else {
			if s.Attributes.ExportTo.Contains(visibility.Public) {
				ps.ServiceIndex.public = append(ps.ServiceIndex.public, s)
				continue
			} else if s.Attributes.ExportTo.Contains(visibility.None) {
				continue
			}
			// . or other namespaces
			for exportTo := range s.Attributes.ExportTo {
				if exportTo == visibility.Private || string(exportTo) == ns {
					ps.ServiceIndex.privateByNamespace[ns] = append(ps.ServiceIndex.privateByNamespace[ns], s)
				} else {
					ps.ServiceIndex.exportedToNamespace[string(exportTo)] = append(ps.ServiceIndex.exportedToNamespace[string(exportTo)], s)
				}
			}
		}
	}

	ps.initServiceAccounts(env, allServices)
}

func (ps *ConfigSnapshot) createNewContext(env *Environment) {
	log.Debug("creating configuration snapshot (full initialization)")
	ps.initServiceRegistry(env, nil)
	// Initialize Kubernetes Gateway API resources if the controller is enabled.
	ps.initKubernetesGateways(env)
	ps.initHTTPRoutes(env)
	ps.initDxgateServices(env)
	ps.initBackendTLSPolicies(env)
	ps.initFaultInjectionPolicies(env)
	ps.initServiceActivationPolicies(env)
	ps.initAuthenticationPolicies(env)
}

func (ps *ConfigSnapshot) updateContext(env *Environment, oldSnapshot *ConfigSnapshot, change *ConfigChange) {
	// A Service may appear after a policy in the same informer burst. Rebuild
	// the registry on the explicit Service event even when the total count was
	// already visible through env.Services(); otherwise one HA replica can keep
	// an activation RDS snapshot that permanently omits the new backend.
	servicesChanged := change != nil &&
		(len(change.AddressesUpdated) > 0 ||
			HasConfigsOfKind(change.ConfigsUpdated, kind.Service) ||
			HasConfigsOfKind(change.ConfigsUpdated, kind.ServiceEntry))

	// Also check if the actual number of services has changed
	// This handles cases where Kubernetes Services are added/removed without ServiceEntry updates
	if !servicesChanged && oldSnapshot != nil {
		currentServices := env.Services()
		// Count services in old ServiceIndex
		oldServiceCount := 0
		for _, namespaces := range oldSnapshot.ServiceIndex.HostnameAndNamespace {
			oldServiceCount += len(namespaces)
		}
		// If service count differs, services have changed
		if len(currentServices) != oldServiceCount {
			servicesChanged = true
		}
	}

	if servicesChanged {
		// Services have changed. initialize service registry
		ps.initServiceRegistry(env, change.ConfigsUpdated)
	} else {
		// make sure we copy over things that would be generated in initServiceRegistry
		ps.ServiceIndex = oldSnapshot.ServiceIndex
		ps.serviceAccounts = oldSnapshot.serviceAccounts
	}

	// Initialize or reuse Gateway API controller state.
	// Gateway status and derived configs depend on services, so recompute
	// if services have changed, otherwise carry over the previous controller.
	if servicesChanged {
		ps.initKubernetesGateways(env)
	} else {
		ps.GatewayAPIController = oldSnapshot.GatewayAPIController
	}

	httpRoutesChanged := change != nil && HasConfigsOfKind(change.ConfigsUpdated, kind.HTTPRoute)

	if httpRoutesChanged {
		log.Debugf("HTTPRoutes changed, re-initializing HTTPRoute index")
		ps.initHTTPRoutes(env)
	} else {
		log.Debugf("HTTPRoutes unchanged, reusing old HTTPRoute index")
		ps.httpRouteIndex = oldSnapshot.httpRouteIndex
	}

	dxgateServicesChanged := change != nil && HasConfigsOfKind(change.ConfigsUpdated, kind.DxgateService)
	if dxgateServicesChanged {
		ps.initDxgateServices(env)
	} else {
		ps.dxgateServiceIndex = oldSnapshot.dxgateServiceIndex
	}

	backendTLSPoliciesChanged := change != nil && HasConfigsOfKind(change.ConfigsUpdated, kind.BackendTLSPolicy)
	if backendTLSPoliciesChanged {
		log.Debugf("BackendTLSPolicies changed, re-initializing BackendTLSPolicy index")
		ps.initBackendTLSPolicies(env)
	} else {
		log.Debugf("BackendTLSPolicies unchanged, reusing old BackendTLSPolicy index")
		ps.backendTLSPolicyIndex = oldSnapshot.backendTLSPolicyIndex
	}

	faultInjectionPoliciesChanged := change != nil && HasConfigsOfKind(change.ConfigsUpdated, kind.FaultInjectionPolicy)
	if faultInjectionPoliciesChanged {
		log.Debugf("FaultInjectionPolicies changed, re-initializing FaultInjectionPolicy index")
		ps.initFaultInjectionPolicies(env)
	} else {
		ps.faultInjectionIndex = oldSnapshot.faultInjectionIndex
	}

	ps.serviceActivationIndex = copyServiceActivationPolicyIndex(oldSnapshot.serviceActivationIndex)
	ps.applyServiceActivationPolicyUpdates(change)

	authnPoliciesChanged := change != nil && (change.Full || authPolicyKindsChanged(change.ConfigsUpdated))
	if authnPoliciesChanged || oldSnapshot == nil || oldSnapshot.AuthenticationPolicies == nil {
		log.Debugf("security authentication policy changed (full=%v, configsUpdatedContainingSecurityPolicy=%v), rebuilding authentication policies",
			change != nil && change.Full, func() bool {
				if change == nil {
					return false
				}
				return authPolicyKindsChanged(change.ConfigsUpdated)
			}())
		ps.initAuthenticationPolicies(env)
	} else {
		ps.AuthenticationPolicies = oldSnapshot.AuthenticationPolicies
	}
}

func authPolicyKindsChanged(configs sets.Set[ConfigKey]) bool {
	return HasConfigsOfKind(configs, kind.PeerAuthentication) ||
		HasConfigsOfKind(configs, kind.RequestAuthentication) ||
		HasConfigsOfKind(configs, kind.AuthorizationPolicy)
}

func (ps *ConfigSnapshot) initAuthenticationPolicies(env *Environment) {
	if env == nil {
		ps.AuthenticationPolicies = nil
		return
	}
	ps.AuthenticationPolicies = initAuthenticationPolicies(env)
}

func (ps *ConfigSnapshot) InboundMTLSModeForProxy(proxy *Proxy, port uint32) MutualTLSMode {
	if ps == nil || proxy == nil || ps.AuthenticationPolicies == nil {
		return MTLSUnknown
	}
	var namespace string
	if proxy.Metadata != nil {
		namespace = proxy.Metadata.Namespace
	}
	if namespace == "" {
		namespace = proxy.ConfigNamespace
	}
	return ps.AuthenticationPolicies.EffectiveMutualTLSMode(namespace, nil, port)
}

func (ps *ConfigSnapshot) RequestAuthenticationsForWorkload(namespace string, workloadLabels map[string]string) []config.Config {
	if ps == nil || ps.AuthenticationPolicies == nil {
		return nil
	}
	return ps.AuthenticationPolicies.RequestAuthenticationsForWorkload(namespace, workloadLabels)
}

func (ps *ConfigSnapshot) AuthorizationPoliciesForWorkload(namespace string, workloadLabels map[string]string) []config.Config {
	if ps == nil || ps.AuthenticationPolicies == nil {
		return nil
	}
	return ps.AuthenticationPolicies.AuthorizationPoliciesForWorkload(namespace, workloadLabels)
}

// initKubernetesGateways initializes Kubernetes Gateway API objects by delegating
// to the GatewayAPIController, if it is present in the Environment.
// This closely follows Dubbo's initKubernetesGateways behavior.
func (ps *ConfigSnapshot) initKubernetesGateways(env *Environment) {
	if env == nil || env.GatewayAPIController == nil {
		return
	}
	ps.GatewayAPIController = env.GatewayAPIController
	env.GatewayAPIController.Reconcile(ps)
}

func (ps *ConfigSnapshot) ServiceForHostname(proxy *Proxy, hostname host.Name) *Service {
	for _, service := range ps.ServiceIndex.HostnameAndNamespace[hostname] {
		return service
	}

	// No service found
	return nil
}

func (ps *ConfigSnapshot) servicesExportedToNamespace(ns string) []*Service {
	var out []*Service

	// First add private services and explicitly exportedTo services
	if ns == NamespaceAll {
		out = make([]*Service, 0, len(ps.ServiceIndex.privateByNamespace)+len(ps.ServiceIndex.public))
		for _, privateServices := range ps.ServiceIndex.privateByNamespace {
			out = append(out, privateServices...)
		}
	} else {
		out = make([]*Service, 0, len(ps.ServiceIndex.privateByNamespace[ns])+
			len(ps.ServiceIndex.exportedToNamespace[ns])+len(ps.ServiceIndex.public))
		out = append(out, ps.ServiceIndex.privateByNamespace[ns]...)
		out = append(out, ps.ServiceIndex.exportedToNamespace[ns]...)
	}

	// Second add public services
	out = append(out, ps.ServiceIndex.public...)

	return out
}

func (ps *ConfigSnapshot) GetAllServices() []*Service {
	return ps.servicesExportedToNamespace(NamespaceAll)
}

func (ps *ConfigSnapshot) initHTTPRoutes(env *Environment) {
	log.Debugf("starting HTTPRoute initialization")
	httproutes := env.List(gvk.HTTPRoute, NamespaceAll)
	log.Debugf("found %d HTTPRoute configs", len(httproutes))

	hostToRoutes := make(map[host.Name][]config.Config)
	for _, hr := range httproutes {
		hrSpec, ok := hr.Spec.(*sigsk8siogatewayapiapisv1.HTTPRouteSpec)
		if !ok {
			log.Debugf("HTTPRoute %s/%s spec is not HTTPRouteSpec", hr.Namespace, hr.Name)
			continue
		}

		// Process hostnames from HTTPRoute
		if len(hrSpec.Hostnames) == 0 {
			// If no hostnames specified, match all
			hostToRoutes["*"] = append(hostToRoutes["*"], hr)
			log.Debugf("indexed HTTPRoute %s/%s for wildcard hostname (no hostnames specified)", hr.Namespace, hr.Name)
		} else {
			for _, hostname := range hrSpec.Hostnames {
				if hostname == "" {
					// Empty hostname means match all
					hostToRoutes["*"] = append(hostToRoutes["*"], hr)
					log.Debugf("indexed HTTPRoute %s/%s for wildcard hostname", hr.Namespace, hr.Name)
				} else {
					hostStr := string(hostname)
					// Resolve shortname to FQDN
					resolvedHost := string(ResolveShortnameToFQDN(hostStr, hr.Meta))
					hostName := host.Name(resolvedHost)
					hostToRoutes[hostName] = append(hostToRoutes[hostName], hr)
					log.Debugf("indexed HTTPRoute %s/%s for hostname %s", hr.Namespace, hr.Name, hostName)
				}
			}
		}
	}
	ps.httpRouteIndex.hostToRoutes = hostToRoutes
	log.Debugf("indexed HTTPRoutes for %d hostnames", len(hostToRoutes))
	if len(hostToRoutes) > 0 {
		for hostname, routes := range hostToRoutes {
			log.Infof("hostname %s has %d HTTPRoute(s)", hostname, len(routes))
		}
	}
}

func (ps *ConfigSnapshot) initDxgateServices(env *Environment) {
	services := sortConfigByCreationTime(env.List(gvk.DxgateService, NamespaceAll))
	index := make(map[string]map[string]config.Config)
	for _, service := range services {
		if index[service.Namespace] == nil {
			index[service.Namespace] = make(map[string]config.Config)
		}
		index[service.Namespace][service.Name] = service
	}
	ps.dxgateServiceIndex = dxgateServiceIndex{byNamespace: index}
}

// DxgateService resolves the mesh-native backend named by an HTTPRoute.
func (ps *ConfigSnapshot) DxgateService(namespace, name string) (config.Config, bool) {
	if ps == nil {
		return config.Config{}, false
	}
	services := ps.dxgateServiceIndex.byNamespace[namespace]
	if services == nil {
		return config.Config{}, false
	}
	service, found := services[name]
	return service, found
}

// HTTPRouteForHost returns HTTPRoutes that match the given hostname.
func (ps *ConfigSnapshot) HTTPRouteForHost(hostname host.Name) []config.Config {
	var routes []config.Config
	hostStr := string(hostname)

	// Special case: if hostname is "*", return ALL HTTPRoutes
	// This is needed for Gateway Pod inbound listeners that need to route traffic based on HTTPRoute hostnames
	if hostname == "*" {
		for _, routeList := range ps.httpRouteIndex.hostToRoutes {
			routes = append(routes, routeList...)
		}
		if len(routes) == 0 {
			log.Debugf("no HTTPRoute found for wildcard hostname")
			return nil
		}
		log.Infof("found %d HTTPRoute(s) for wildcard hostname", len(routes))
		return routes
	}

	// First check exact match
	if exactRoutes, ok := ps.httpRouteIndex.hostToRoutes[hostname]; ok {
		routes = append(routes, exactRoutes...)
	}

	// Check wildcard patterns (e.g., *.example.com)
	for patternHost, patternRoutes := range ps.httpRouteIndex.hostToRoutes {
		if patternHost == "*" {
			continue // Skip global wildcard, handle separately
		}
		patternStr := string(patternHost)
		if strings.HasPrefix(patternStr, "*.") {
			// Wildcard pattern like *.example.com
			suffix := patternStr[2:] // Remove "*."
			if strings.HasSuffix(hostStr, suffix) {
				routes = append(routes, patternRoutes...)
			}
		}
	}

	// Then check global wildcard
	if wildcardRoutes, ok := ps.httpRouteIndex.hostToRoutes["*"]; ok {
		routes = append(routes, wildcardRoutes...)
	}

	if len(routes) == 0 {
		log.Debugf("no HTTPRoute found for hostname %s", hostname)
		return nil
	}

	log.Infof("found %d HTTPRoute(s) for hostname %s", len(routes), hostname)
	return routes
}

func (ps *ConfigSnapshot) initBackendTLSPolicies(env *Environment) {
	policies := sortConfigByCreationTime(env.List(gvk.BackendTLSPolicy, NamespaceAll))
	serviceTLS := map[string]BackendTLSSettings{}
	for _, cfg := range policies {
		spec, ok := cfg.Spec.(*sigsk8siogatewayapiapisv1.BackendTLSPolicySpec)
		if !ok {
			log.Debugf("BackendTLSPolicy %s/%s spec is not BackendTLSPolicySpec", cfg.Namespace, cfg.Name)
			continue
		}
		if !supportsSystemBackendTLS(spec) {
			continue
		}
		settings := BackendTLSSettings{SNI: string(spec.Validation.Hostname)}
		for _, target := range spec.TargetRefs {
			if !isBackendTLSPolicyServiceTarget(target) {
				continue
			}
			key := backendTLSPolicyServiceKey(cfg.Namespace, string(target.Name))
			if _, found := serviceTLS[key]; !found {
				serviceTLS[key] = settings
			}
		}
	}
	ps.backendTLSPolicyIndex.serviceTLS = serviceTLS
	log.Debugf("indexed BackendTLSPolicies for %d services", len(serviceTLS))
}

func (ps *ConfigSnapshot) BackendTLSForService(namespace, name string) (BackendTLSSettings, bool) {
	if ps == nil || ps.backendTLSPolicyIndex.serviceTLS == nil {
		return BackendTLSSettings{}, false
	}
	settings, found := ps.backendTLSPolicyIndex.serviceTLS[backendTLSPolicyServiceKey(namespace, name)]
	return settings, found
}

type FaultInjectionSettings struct {
	Delay           time.Duration
	DelayPercentage uint32
	AbortStatus     uint32
	AbortPercentage uint32
}

type faultInjectionPolicyIndex struct {
	serviceFaults map[string]FaultInjectionSettings
}

func (ps *ConfigSnapshot) initFaultInjectionPolicies(env *Environment) {
	policies := sortConfigByCreationTime(env.List(gvk.FaultInjectionPolicy, NamespaceAll))
	serviceFaults := map[string]FaultInjectionSettings{}
	for _, cfg := range policies {
		spec, ok := cfg.Spec.(*networking.FaultInjectionPolicy)
		if !ok || spec == nil {
			continue
		}
		settings := FaultInjectionSettings{}
		if delay := spec.GetDelay(); delay != nil {
			if value := delay.GetFixedDelay(); value != nil && value.CheckValid() == nil && value.AsDuration() > 0 {
				settings.Delay = value.AsDuration()
				settings.DelayPercentage = faultPercentage(delay.GetPercentage())
			}
		}
		if abort := spec.GetAbort(); abort != nil && abort.GetHttpStatus() >= 400 && abort.GetHttpStatus() <= 599 {
			settings.AbortStatus = abort.GetHttpStatus()
			settings.AbortPercentage = faultPercentage(abort.GetPercentage())
		}
		if settings.Delay == 0 && settings.AbortStatus == 0 {
			continue
		}
		for _, target := range spec.GetTargetRefs() {
			if !isFaultInjectionServiceTarget(target) {
				continue
			}
			key := faultInjectionServiceKey(cfg.Namespace, target.GetName(), target.GetSectionName())
			if _, found := serviceFaults[key]; !found {
				serviceFaults[key] = settings
			}
		}
	}
	ps.faultInjectionIndex.serviceFaults = serviceFaults
	log.Debugf("indexed FaultInjectionPolicies for %d service targets", len(serviceFaults))
}

func (ps *ConfigSnapshot) FaultInjectionForService(namespace, name, portName string) (FaultInjectionSettings, bool) {
	if ps == nil || ps.faultInjectionIndex.serviceFaults == nil {
		return FaultInjectionSettings{}, false
	}
	if portName != "" {
		if settings, found := ps.faultInjectionIndex.serviceFaults[faultInjectionServiceKey(namespace, name, portName)]; found {
			return settings, true
		}
	}
	settings, found := ps.faultInjectionIndex.serviceFaults[faultInjectionServiceKey(namespace, name, "")]
	return settings, found
}

func faultPercentage(value *wrapperspb.UInt32Value) uint32 {
	if value == nil {
		return 100
	}
	return value.GetValue()
}

func isFaultInjectionServiceTarget(target *networking.PolicyTargetReference) bool {
	if target == nil || target.GetName() == "" {
		return false
	}
	group := strings.TrimSpace(target.GetGroup())
	return (group == "" || group == "core") && target.GetKind() == "Service"
}

func faultInjectionServiceKey(namespace, name, section string) string {
	return namespace + "/" + name + "#" + section
}

func supportsSystemBackendTLS(spec *sigsk8siogatewayapiapisv1.BackendTLSPolicySpec) bool {
	if spec == nil || spec.Validation.Hostname == "" {
		return false
	}
	wellKnown := spec.Validation.WellKnownCACertificates
	return wellKnown != nil && *wellKnown == sigsk8siogatewayapiapisv1.WellKnownCACertificatesSystem
}

func isBackendTLSPolicyServiceTarget(target sigsk8siogatewayapiapisv1.LocalPolicyTargetReferenceWithSectionName) bool {
	if target.SectionName != nil {
		return false
	}
	group := strings.TrimSpace(string(target.Group))
	kind := strings.TrimSpace(string(target.Kind))
	return (group == "" || group == "core") && strings.EqualFold(kind, "Service")
}

func backendTLSPolicyServiceKey(namespace, name string) string {
	return namespace + "/" + name
}

// ServiceAccounts returns the SPIFFE identities associated with the workloads
// backing the given service hostname in the given namespace. The returned list
// is sorted and already expanded with trust domain aliases.
func (ps *ConfigSnapshot) ServiceAccounts(hostname host.Name, namespace string) []string {
	return ps.serviceAccounts[serviceAccountKey{hostname: hostname, namespace: namespace}]
}

// ServiceActivationEnabled reports whether a structurally valid policy targets
// this Service. The live ActivatorReady condition cannot gate routing: the first
// cold request is what makes an Activator report demand for this target.
func (ps *ConfigSnapshot) ServiceActivationEnabled(namespace, name string) bool {
	if ps == nil {
		return false
	}
	_, found := ps.serviceActivationIndex.services[backendTLSPolicyServiceKey(namespace, name)]
	return found
}

// ActivationGatewayService returns the dedicated namespace-local Activator.
func (ps *ConfigSnapshot) ActivationGatewayService(namespace string) *Service {
	if ps == nil {
		return nil
	}
	for _, namespaces := range ps.ServiceIndex.HostnameAndNamespace {
		if svc := namespaces[namespace]; svc != nil && svc.Attributes.Name == ActivationGatewayServiceName {
			return svc
		}
	}
	return nil
}

// ActivationGatewaySANs is stable across cold/hot EDS transitions. Keeping the
// backend and Activator identities in one CDS validation context avoids a TLS
// verification window while the endpoint assignment changes.
func (ps *ConfigSnapshot) ActivationGatewaySANs(namespace string) []string {
	if ps == nil || ps.Mesh == nil || namespace == "" {
		return nil
	}
	identities := sets.New(spiffe.MustGenSpiffeURI(ps.Mesh, namespace, ActivationGatewayServiceName))
	return sets.SortedList(spiffe.ExpandWithTrustDomains(identities, ps.Mesh.TrustDomainAliases))
}

// ActivationBackendSANs returns the backend identities declared by the policy.
// Unlike endpoint-derived identities, these remain available when dubbod starts
// while the target has zero endpoints.
func (ps *ConfigSnapshot) ActivationBackendSANs(namespace, name string) []string {
	if ps == nil || ps.Mesh == nil || namespace == "" {
		return nil
	}
	accounts, found := ps.serviceActivationIndex.services[backendTLSPolicyServiceKey(namespace, name)]
	if !found {
		return nil
	}
	identities := sets.New[string]()
	for _, account := range accounts {
		account = strings.TrimSpace(account)
		if account == "" {
			continue
		}
		if strings.HasPrefix(account, "spiffe://") {
			identities.Insert(account)
			continue
		}
		generated := sets.New(spiffe.MustGenSpiffeURI(ps.Mesh, namespace, account))
		identities.InsertAll(sets.SortedList(
			spiffe.ExpandWithTrustDomains(generated, ps.Mesh.TrustDomainAliases),
		)...)
	}
	return sets.SortedList(identities)
}

func (ps *ConfigSnapshot) ActivatedServices(namespace string) []*Service {
	if ps == nil {
		return nil
	}
	out := make([]*Service, 0)
	for _, namespaces := range ps.ServiceIndex.HostnameAndNamespace {
		svc := namespaces[namespace]
		if svc != nil && ps.ServiceActivationEnabled(namespace, svc.Attributes.Name) {
			out = append(out, svc)
		}
	}
	return SortServicesByCreationTime(out)
}

func (ps *ConfigSnapshot) initServiceActivationPolicies(env *Environment) {
	ps.serviceActivationIndex = serviceActivationPolicyIndex{services: map[string][]string{}}
	if env == nil {
		return
	}
	configs := sortConfigByCreationTime(env.List(gvk.ServiceActivationPolicy, NamespaceAll))
	for _, cfg := range configs {
		ps.upsertServiceActivationPolicy(cfg)
	}
	log.Debugf("activation policy index rebuilt: configs=%d services=%d", len(configs), len(ps.serviceActivationIndex.services))
}

func copyServiceActivationPolicyIndex(in serviceActivationPolicyIndex) serviceActivationPolicyIndex {
	out := serviceActivationPolicyIndex{services: make(map[string][]string, len(in.services))}
	for key, accounts := range in.services {
		out.services[key] = append([]string(nil), accounts...)
	}
	return out
}

func (ps *ConfigSnapshot) applyServiceActivationPolicyUpdates(change *ConfigChange) {
	if change == nil {
		return
	}
	for _, update := range change.ServiceActivationPolicyUpdates {
		if update.Previous.Spec != nil {
			ps.deleteServiceActivationPolicy(update.Previous)
		}
		if update.Deleted {
			ps.deleteServiceActivationPolicy(update.Config)
			continue
		}
		ps.upsertServiceActivationPolicy(update.Config)
	}
}

func (ps *ConfigSnapshot) deleteServiceActivationPolicy(cfg config.Config) {
	spec, ok := cfg.Spec.(*networking.ServiceActivationPolicy)
	if ok && spec != nil && spec.GetTargetRef() != nil {
		delete(ps.serviceActivationIndex.services,
			backendTLSPolicyServiceKey(cfg.Namespace, spec.GetTargetRef().GetName()))
	}
}

func (ps *ConfigSnapshot) upsertServiceActivationPolicy(cfg config.Config) {
	spec, ok := cfg.Spec.(*networking.ServiceActivationPolicy)
	if !ok || spec == nil || spec.GetTargetRef() == nil || spec.GetAutoscalerRef() == nil {
		return
	}
	target := spec.GetTargetRef()
	if strings.TrimSpace(target.GetName()) == "" ||
		(target.GetKind() != "" && !strings.EqualFold(target.GetKind(), "Service")) ||
		strings.TrimSpace(target.GetGroup()) != "" ||
		strings.TrimSpace(spec.GetAutoscalerRef().GetName()) == "" ||
		len(spec.GetBackendServiceAccounts()) == 0 {
		return
	}
	ps.serviceActivationIndex.services[backendTLSPolicyServiceKey(cfg.Namespace, target.GetName())] =
		append([]string(nil), spec.GetBackendServiceAccounts()...)
}

func (ps *ConfigSnapshot) initServiceAccounts(env *Environment, services []*Service) {
	for _, svc := range services {
		var accounts sets.String
		// First get endpoint level service accounts
		shard, f := env.EndpointIndex.ShardsForService(string(svc.Hostname), svc.Attributes.Namespace)
		if f {
			shard.RLock()
			accounts = shard.ServiceAccounts.Copy()
			shard.RUnlock()
		}
		if len(svc.ServiceAccounts) > 0 {
			if accounts == nil {
				accounts = sets.New(svc.ServiceAccounts...)
			} else {
				accounts = accounts.InsertAll(svc.ServiceAccounts...)
			}
		}
		sa := sets.SortedList(spiffe.ExpandWithTrustDomains(accounts, ps.Mesh.TrustDomainAliases))
		key := serviceAccountKey{
			hostname:  svc.Hostname,
			namespace: svc.Attributes.Namespace,
		}
		ps.serviceAccounts[key] = sa
	}
}
