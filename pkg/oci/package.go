package oci

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/docker/docker-agent/pkg/config"
	"github.com/docker/docker-agent/pkg/config/latest"
	"github.com/docker/docker-agent/pkg/content"
	"github.com/docker/docker-agent/pkg/oci/crypto"
	"github.com/docker/docker-agent/pkg/version"
)

// EncryptedConfigAnnotation is the OCI annotation key under which the full
// agent YAML is stored, encrypted with a caller-supplied shared key. A holder
// of the same key can recover the original YAML and is guaranteed (by the
// authenticated cipher) that it has not been modified.
const EncryptedConfigAnnotation = "io.docker.agent.config.encrypted"

// packageOptions holds the optional behaviour of PackageFileAsOCIToStore.
type packageOptions struct {
	encryptKey string
}

// PackageOption customizes how an agent file is packaged as an OCI artifact.
type PackageOption func(*packageOptions)

// WithEncryptedConfig stores the full agent YAML, encrypted with the given
// shared key, in an OCI annotation. When key is empty the option is a no-op.
// The encryption is authenticated, so a consumer holding the same key can both
// decrypt the YAML and verify it has not been tampered with.
func WithEncryptedConfig(key string) PackageOption {
	return func(o *packageOptions) {
		o.encryptKey = key
	}
}

// PackageFileAsOCIToStore creates an OCI artifact from a file and stores it in the content store
func PackageFileAsOCIToStore(ctx context.Context, agentSource config.Source, artifactRef string, store *content.Store, opts ...PackageOption) (string, error) {
	var options packageOptions
	for _, opt := range opts {
		opt(&options)
	}

	if !strings.Contains(artifactRef, ":") {
		artifactRef += ":latest"
	}

	cfg, err := config.Load(ctx, agentSource)
	if err != nil {
		return "", fmt.Errorf("loading config: %w", err)
	}

	// Read raw data
	var raw struct {
		Version string `yaml:"version,omitempty"`
	}
	data, err := agentSource.Read(ctx)
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return "", fmt.Errorf("looking for version in config file\n%s", yaml.FormatError(err, true, true))
	}

	// Push a self-contained artifact. Normally we preserve the author's raw
	// bytes (keeping comments and formatting), but we must serialize the
	// resolved config instead when either:
	//   - the config has no version (we inject the latest one), or
	//   - any agent uses instruction_file: its contents have already been
	//     inlined into Instruction by config.Load, and a pulled artifact has
	//     no local directory to resolve the original path against, so the raw
	//     reference would be unreadable.
	if raw.Version == "" || configUsesInstructionFile(data) {
		cfg.Version = cmp.Or(raw.Version, latest.Version)
		data, err = yaml.MarshalWithOptions(cfg, yaml.Indent(2))
		if err != nil {
			return "", fmt.Errorf("marshaling config: %w", err)
		}
	}

	// Prepare OCI annotations
	annotations := map[string]string{
		"io.docker.cagent.version":             version.Version,
		"io.docker.agent.version":              version.Version,
		"org.opencontainers.image.created":     time.Now().Format(time.RFC3339),
		"org.opencontainers.image.description": "OCI artifact containing " + filepath.Base(agentSource.Name()),
	}
	if author := cfg.Metadata.Author; author != "" {
		annotations["org.opencontainers.image.authors"] = author
	}
	if license := cfg.Metadata.License; license != "" {
		annotations["org.opencontainers.image.licenses"] = license
	}
	if revision := cfg.Metadata.Version; revision != "" {
		annotations["org.opencontainers.image.revision"] = revision
	}
	if len(cfg.Metadata.Tags) > 0 {
		annotations["io.docker.agent.tags"] = strings.Join(cfg.Metadata.Tags, ",")
	}

	// Optionally embed the full YAML, encrypted with a shared key, as an
	// annotation. The bytes are exactly what we push as the layer, so a
	// consumer with the key recovers the same self-contained config.
	if options.encryptKey != "" {
		encrypted, err := crypto.Encrypt(options.encryptKey, data)
		if err != nil {
			return "", fmt.Errorf("encrypting config: %w", err)
		}
		annotations[EncryptedConfigAnnotation] = encrypted
	}

	layer := static.NewLayer(data, "application/yaml")
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return "", fmt.Errorf("appending layer: %w", err)
	}

	// Convert to OCI manifest format to support annotations
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, "application/vnd.docker.agent.config.v1+json")
	img = mutate.Annotations(img, annotations).(v1.Image)

	digest, err := store.StoreArtifact(img, artifactRef)
	if err != nil {
		return "", fmt.Errorf("storing artifact in content store: %w", err)
	}

	return digest, nil
}

// configUsesInstructionFile reports whether any agent in the raw config sets a
// non-empty instruction_file (either a single string or a non-empty list). It
// is a best-effort, format-tolerant probe: a parse failure (e.g. HCL) simply
// yields false, in which case the caller falls back to its version-based
// decision.
func configUsesInstructionFile(data []byte) bool {
	var probe map[string]any
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return false
	}
	agents, ok := probe["agents"].(map[string]any)
	if !ok {
		return false
	}
	for _, v := range agents {
		agent, ok := v.(map[string]any)
		if !ok {
			continue
		}
		switch ref := agent["instruction_file"].(type) {
		case string:
			if ref != "" {
				return true
			}
		case []any:
			for _, item := range ref {
				if s, ok := item.(string); ok && s != "" {
					return true
				}
			}
		}
	}
	return false
}
