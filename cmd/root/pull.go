package root

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/docker/docker-agent/pkg/cli"
	"github.com/docker/docker-agent/pkg/content"
	"github.com/docker/docker-agent/pkg/oci"
	"github.com/docker/docker-agent/pkg/oci/crypto"
	"github.com/docker/docker-agent/pkg/remote"
	"github.com/docker/docker-agent/pkg/telemetry"
)

type pullFlags struct {
	force      bool
	decryptKey bool
}

func newPullCmd() *cobra.Command {
	var flags pullFlags

	cmd := &cobra.Command{
		Use:   "pull <registry-ref>",
		Short: "Pull an agent from an OCI registry",
		Long: `Pull an agent configuration file from an OCI registry.

With --decrypt-key, the full YAML is recovered from the encrypted OCI
annotation instead of the pushed layer. The shared key is read from the ` +
			encryptKeyEnvVar + ` environment variable, or prompted for interactively.
Decryption fails if the key is wrong or the annotation has been modified,
which guarantees the recovered YAML is authentic.`,
		Args: cobra.ExactArgs(1),
		RunE: flags.runPullCommand,
	}

	cmd.PersistentFlags().BoolVar(&flags.force, "force", false, "Force pull even if the configuration already exists locally")
	cmd.Flags().BoolVar(&flags.decryptKey, "decrypt-key", false,
		"Recover the full YAML from the encrypted OCI annotation using a shared key "+
			"(key read from "+encryptKeyEnvVar+" or prompted)")

	return cmd
}

func (f *pullFlags) runPullCommand(cmd *cobra.Command, args []string) (commandErr error) {
	ctx := cmd.Context()
	telemetry.TrackCommand(ctx, "share", append([]string{"pull"}, args...))
	defer func() { // do not inline this defer so that commandErr is not resolved early
		telemetry.TrackCommandError(ctx, "share", append([]string{"pull"}, args...), commandErr)
	}()

	out := cli.NewPrinter(cmd.OutOrStdout())
	registryRef := args[0]
	slog.DebugContext(ctx, "Starting pull", "registry_ref", registryRef)

	out.Println("Pulling agent", registryRef)

	_, err := remote.Pull(ctx, registryRef, f.force)
	if err != nil {
		return fmt.Errorf("failed to pull artifact: %w", err)
	}

	store, err := content.NewStore()
	if err != nil {
		return fmt.Errorf("failed to open content store: %w", err)
	}

	var yamlFile string
	if f.decryptKey {
		yamlFile, err = decryptConfigFromAnnotations(store, registryRef)
		if err != nil {
			return err
		}
		out.Println("Recovered and verified the full YAML from the encrypted annotation")
	} else {
		yamlFile, err = store.GetArtifact(registryRef)
		if err != nil {
			return fmt.Errorf("failed to get agent yaml: %w", err)
		}
	}

	agentName := strings.ReplaceAll(registryRef, "/", "_")
	fileName := agentName + ".yaml"

	if err := os.WriteFile(fileName, []byte(yamlFile), 0o644); err != nil { //nolint:gosec // pulled agent yaml is meant to be readable
		return err
	}

	out.Printf("Agent saved to %s\n", fileName)

	return nil
}

// decryptConfigFromAnnotations reads the encrypted-config annotation off the
// stored artifact and decrypts it with the shared key. Decryption fails if the
// key is wrong or the annotation was tampered with.
func decryptConfigFromAnnotations(store *content.Store, registryRef string) (string, error) {
	metadata, err := store.GetArtifactMetadata(registryRef)
	if err != nil {
		return "", fmt.Errorf("failed to read artifact metadata: %w", err)
	}

	payload, ok := metadata.Annotations[oci.EncryptedConfigAnnotation]
	if !ok || payload == "" {
		return "", fmt.Errorf("artifact has no encrypted config annotation (%s); it was not pushed with --encrypt-key", oci.EncryptedConfigAnnotation)
	}

	key, err := resolveEncryptionKey("Decryption key: ")
	if err != nil {
		return "", err
	}

	plaintext, err := crypto.Decrypt(key, payload)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt config: %w", err)
	}

	return string(plaintext), nil
}
