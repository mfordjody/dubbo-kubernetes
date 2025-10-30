package bootstrap

import (
	"encoding/json"
	"fmt"
	"github.com/apache/dubbo-kubernetes/pkg/config/constants"
	"github.com/apache/dubbo-kubernetes/pkg/model"
	"github.com/apache/dubbo-kubernetes/pkg/ptr"
	"github.com/apache/dubbo-kubernetes/pkg/security"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	meshAPI "istio.io/api/mesh/v1alpha1"
	"k8s.io/klog/v2"
	"os"
	"strconv"
	"strings"
)

const (
	DubboMetaPrefix     = "DUBBO_META_"
	DubboMetaJSONPrefix = "DUBBO_METAJSON_"
)

type MetadataOptions struct {
	ID                     string
	InstanceIPs            []string
	StsPort                int
	ProxyConfig            *meshAPI.ProxyConfig
	SailSubjectAltName     []string
	CredentialSocketExists bool
	XDSRootCert            string
	annotationFilePath     string
	MetadataDiscovery      *bool
	Envs                   []string
}

func ReadPodAnnotations(path string) (map[string]string, error) {
	if path == "" {
		path = constants.PodInfoAnnotationsPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseDownwardAPI(string(b))
}

func ParseDownwardAPI(i string) (map[string]string, error) {
	res := map[string]string{}
	for _, line := range strings.Split(i, "\n") {
		sl := strings.SplitN(line, "=", 2)
		if len(sl) != 2 {
			continue
		}
		key := sl[0]
		// Strip the leading/trailing quotes
		val, err := strconv.Unquote(sl[1])
		if err != nil {
			return nil, fmt.Errorf("failed to unquote %v: %v", sl[1], err)
		}
		res[key] = val
	}
	return res, nil
}

func shouldExtract(envVar, prefix string) bool {
	return strings.HasPrefix(envVar, prefix)
}

func isEnvVar(str string) bool {
	return strings.Contains(str, "=")
}

func parseEnvVar(varStr string) (string, string) {
	parts := strings.SplitN(varStr, "=", 2)
	if len(parts) != 2 {
		return varStr, ""
	}
	return parts[0], parts[1]
}

type setMetaFunc func(m map[string]any, key string, val string)

func extractMetadata(envs []string, prefix string, set setMetaFunc, meta map[string]any) {
	metaPrefixLen := len(prefix)
	for _, e := range envs {
		if !shouldExtract(e, prefix) {
			continue
		}
		v := e[metaPrefixLen:]
		if !isEnvVar(v) {
			continue
		}
		metaKey, metaVal := parseEnvVar(v)
		set(meta, metaKey, metaVal)
	}
}

func GetNodeMetaData(options MetadataOptions) (*model.Node, error) {
	meta := &model.BootstrapNodeMetadata{}
	untypedMeta := map[string]any{}

	for k, v := range options.ProxyConfig.GetProxyMetadata() {
		if strings.HasPrefix(k, DubboMetaPrefix) {
			untypedMeta[strings.TrimPrefix(k, DubboMetaPrefix)] = v
		}
	}

	extractMetadata(options.Envs, DubboMetaPrefix, func(m map[string]any, key string, val string) {
		m[key] = val
	}, untypedMeta)

	extractMetadata(options.Envs, DubboMetaJSONPrefix, func(m map[string]any, key string, val string) {
		err := json.Unmarshal([]byte(val), &m)
		if err != nil {
			klog.Warningf("Env variable %s [%s] failed json unmarshal: %v", key, val, err)
		}
	}, untypedMeta)

	j, err := json.Marshal(untypedMeta)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(j, meta); err != nil {
		return nil, err
	}

	if options.StsPort != 0 {
		meta.StsPort = strconv.Itoa(options.StsPort)
	}

	if options.MetadataDiscovery == nil {
		meta.MetadataDiscovery = nil
	} else {
		meta.MetadataDiscovery = ptr.Of(model.StringBool(*options.MetadataDiscovery))
	}

	meta.ProxyConfig = (*model.NodeMetaProxyConfig)(options.ProxyConfig)
	meta.SailSubjectAltName = options.SailSubjectAltName
	meta.XDSRootCert = options.XDSRootCert
	if options.CredentialSocketExists {
		untypedMeta[security.CredentialMetaDataName] = "true"
	}
	var l *core.Locality
	return &model.Node{
		ID:          options.ID,
		Metadata:    meta,
		RawMetadata: untypedMeta,
		Locality:    l,
	}, nil
}
