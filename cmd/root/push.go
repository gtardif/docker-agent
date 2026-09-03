package root

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/docker/docker-agent/pkg/cli"
	"github.com/docker/docker-agent/pkg/config"
	"github.com/docker/docker-agent/pkg/content"
	"github.com/docker/docker-agent/pkg/oci"
	"github.com/docker/docker-agent/pkg/remote"
	"github.com/docker/docker-agent/pkg/telemetry"
)

// encryptKeyEnvVar is an alternative, more secure way to supply the encryption
// key: it keeps the secret out of shell history and process listings.
const encryptKeyEnvVar = "DOCKER_AGENT_ENCRYPT_KEY"

type pushFlags struct {
	encryptKey bool
}

func newPushCmd() *cobra.Command {
	var flags pushFlags

	cmd := &cobra.Command{
		Use:   "push <agent-file> <registry-ref>",
		Short: "Push an agent to an OCI registry",
		Long: `Push an agent configuration file to an OCI registry.

With --encrypt-key, the full agent YAML is additionally encrypted with a shared
key and stored in an OCI annotation. Anyone who knows the same key can recover
the original YAML from the annotation, and the authenticated encryption
guarantees the recovered YAML has not been modified. The key is read from the
` + encryptKeyEnvVar + ` environment variable, or prompted for interactively.`,
		Args: cobra.ExactArgs(2),
		RunE: flags.runPushCommand,
	}

	cmd.Flags().BoolVar(&flags.encryptKey, "encrypt-key", false,
		"Encrypt the full YAML with a shared key and store it in an OCI annotation "+
			"(key read from "+encryptKeyEnvVar+" or prompted)")

	return cmd
}

func (f *pushFlags) runPushCommand(cmd *cobra.Command, args []string) (commandErr error) {
	ctx := cmd.Context()
	telemetry.TrackCommand(ctx, "share", append([]string{"push"}, args...))
	defer func() { // do not inline this defer so that commandErr is not resolved early
		telemetry.TrackCommandError(ctx, "share", append([]string{"push"}, args...), commandErr)
	}()

	agentFilename := args[0]
	tag := args[1]
	out := cli.NewPrinter(cmd.OutOrStdout())

	var packageOpts []oci.PackageOption
	if f.encryptKey {
		key, err := resolveEncryptionKey("Encryption key: ")
		if err != nil {
			return err
		}
		packageOpts = append(packageOpts, oci.WithEncryptedConfig(key))
	}

	store, err := content.NewStore()
	if err != nil {
		return err
	}

	agentSource, err := config.Resolve(agentFilename, nil)
	if err != nil {
		return fmt.Errorf("resolving agent file: %w", err)
	}

	_, err = oci.PackageFileAsOCIToStore(ctx, agentSource, tag, store, packageOpts...)
	if err != nil {
		return fmt.Errorf("failed to build artifact: %w", err)
	}

	slog.DebugContext(ctx, "Starting push", "registry_ref", tag)

	out.Printf("Pushing agent %s to %s\n", agentFilename, tag)

	err = remote.Push(ctx, tag)
	if err != nil {
		return fmt.Errorf("failed to push artifact: %w", err)
	}

	out.Printf("Successfully pushed artifact to %s\n", tag)
	return nil
}

// resolveEncryptionKey reads the shared encryption/decryption key from the
// environment, falling back to an interactive (non-echoing) prompt. It never
// accepts an empty key.
func resolveEncryptionKey(prompt string) (string, error) {
	if key := os.Getenv(encryptKeyEnvVar); key != "" {
		return key, nil
	}

	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return "", fmt.Errorf("no encryption key available: set %s or run in an interactive terminal", encryptKeyEnvVar)
	}

	fmt.Fprint(os.Stdout, prompt)
	// Read directly from the terminal fd so the key does not echo.
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stdout)
	if err != nil {
		return "", fmt.Errorf("reading encryption key: %w", err)
	}
	key := string(value)
	if key == "" {
		return "", fmt.Errorf("encryption key must not be empty (set %s or enter a key)", encryptKeyEnvVar)
	}
	return key, nil
}
