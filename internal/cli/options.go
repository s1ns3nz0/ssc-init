package cli

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/s1ns3nz0/ssc-init/internal/platform"
)

// ErrInvalidOptions is intentionally value-free so callers never echo a
// supplied path or flag value when reporting invalid command arguments.
var ErrInvalidOptions = errors.New("invalid command arguments")

// Options is the fully parsed command line accepted by SSC Init.
type Options struct {
	Command        string
	JSON           bool
	Pretty         bool
	Baseline       bool
	ExternalProbes bool
	ProjectRoots   []string

	// Install inputs. The source is an absolute host path an adapter already
	// obtained; it is handed to the installer and never reported back.
	InstallSource  string
	InstallVersion string
	InstallDigest  string

	PolicyCommand string
	PolicyPath    string
	PolicyAssetID string

	BundleCommand           string
	BundleFamily            string
	BundleSource            string
	BundleSignature         string
	WebhookURL              string
	AdapterCommand          string
	QuarantineCommand       string
	QuarantineAssetID       string
	QuarantineObservationID string
	QuarantineEvidenceID    string
	QuarantineRecordID      string
	QuarantineApprovalID    string
}

// ParseOptions accepts only documented, command-aware argument forms.
func ParseOptions(args []string) (Options, error) {
	if len(args) == 0 {
		return Options{}, ErrInvalidOptions
	}
	options := Options{Command: args[0]}
	switch options.Command {
	case "scan":
		if err := parseScanOptions(args[1:], &options); err != nil {
			return Options{}, err
		}
	case "status":
		if len(args) != 2 {
			return Options{}, ErrInvalidOptions
		}
		switch args[1] {
		case "--json":
			options.JSON = true
		case "--pretty":
			options.Pretty = true
		default:
			return Options{}, ErrInvalidOptions
		}
	case "findings":
		for index := 1; index < len(args); index++ {
			switch args[index] {
			case "--json":
				if options.JSON || options.Pretty {
					return Options{}, ErrInvalidOptions
				}
				options.JSON = true
			case "--pretty":
				if options.JSON || options.Pretty {
					return Options{}, ErrInvalidOptions
				}
				options.Pretty = true
			case "--webhook":
				index++
				if index == len(args) || options.WebhookURL != "" || !validWebhookURL(args[index]) {
					return Options{}, ErrInvalidOptions
				}
				options.WebhookURL = args[index]
			default:
				return Options{}, ErrInvalidOptions
			}
		}
		if !options.JSON && !options.Pretty {
			return Options{}, ErrInvalidOptions
		}
	case "doctor", "version":
		if len(args) != 2 || args[1] != "--json" {
			return Options{}, ErrInvalidOptions
		}
		options.JSON = true
	case "install":
		if err := parseInstallOptions(args[1:], &options); err != nil {
			return Options{}, err
		}
	case "rollback":
		if len(args) != 2 || args[1] != "--json" {
			return Options{}, ErrInvalidOptions
		}
		options.JSON = true
	case "policy":
		if err := parsePolicyOptions(args[1:], &options); err != nil {
			return Options{}, err
		}
	case "bundle":
		if err := parseBundleOptions(args[1:], &options); err != nil {
			return Options{}, err
		}
	case "adapter":
		if len(args) != 2 || args[1] != "evaluate" {
			return Options{}, ErrInvalidOptions
		}
		options.AdapterCommand = args[1]
	case "quarantine":
		if err := parseQuarantineOptions(args[1:], &options); err != nil {
			return Options{}, err
		}
	case "hook":
		if len(args) != 1 {
			return Options{}, ErrInvalidOptions
		}
	default:
		return Options{}, ErrInvalidOptions
	}
	return options, nil
}

func parseQuarantineOptions(args []string, options *Options) error {
	if len(args) == 0 {
		return ErrInvalidOptions
	}
	options.QuarantineCommand = args[0]
	if options.QuarantineCommand != "preview" && options.QuarantineCommand != "apply" && options.QuarantineCommand != "restore-preview" && options.QuarantineCommand != "restore-apply" {
		return ErrInvalidOptions
	}
	for index := 1; index < len(args); index++ {
		flag := args[index]
		if flag == "--json" {
			if options.JSON {
				return ErrInvalidOptions
			}
			options.JSON = true
			continue
		}
		index++
		if index == len(args) || args[index] == "" || strings.ContainsRune(args[index], '\x00') || len(args[index]) > 512 {
			return ErrInvalidOptions
		}
		value := args[index]
		switch flag {
		case "--asset-id":
			if options.QuarantineAssetID != "" {
				return ErrInvalidOptions
			}
			options.QuarantineAssetID = value
		case "--observation-id":
			if options.QuarantineObservationID != "" {
				return ErrInvalidOptions
			}
			options.QuarantineObservationID = value
		case "--evidence-id":
			if options.QuarantineEvidenceID != "" {
				return ErrInvalidOptions
			}
			options.QuarantineEvidenceID = value
		case "--record-id":
			if options.QuarantineRecordID != "" {
				return ErrInvalidOptions
			}
			options.QuarantineRecordID = value
		case "--approval-id":
			if options.QuarantineApprovalID != "" {
				return ErrInvalidOptions
			}
			options.QuarantineApprovalID = value
		default:
			return ErrInvalidOptions
		}
	}
	if !options.JSON {
		return ErrInvalidOptions
	}
	selection := options.QuarantineAssetID != "" && options.QuarantineObservationID != "" && options.QuarantineEvidenceID != "" && options.QuarantineRecordID == ""
	restore := options.QuarantineRecordID != "" && options.QuarantineAssetID == "" && options.QuarantineObservationID == "" && options.QuarantineEvidenceID == ""
	switch options.QuarantineCommand {
	case "preview":
		return requireQuarantineForm(selection && options.QuarantineApprovalID == "")
	case "apply":
		return requireQuarantineForm(selection && options.QuarantineApprovalID != "")
	case "restore-preview":
		return requireQuarantineForm(restore && options.QuarantineApprovalID == "")
	default:
		return requireQuarantineForm(restore && options.QuarantineApprovalID != "")
	}
}

func requireQuarantineForm(valid bool) error {
	if !valid {
		return ErrInvalidOptions
	}
	return nil
}

func validWebhookURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func parseBundleOptions(args []string, options *Options) error {
	if len(args) == 0 {
		return ErrInvalidOptions
	}
	options.BundleCommand = args[0]
	if options.BundleCommand != "install" && options.BundleCommand != "status" && options.BundleCommand != "rollback" {
		return ErrInvalidOptions
	}
	for index := 1; index < len(args); index++ {
		flag := args[index]
		if flag == "--json" {
			if options.JSON {
				return ErrInvalidOptions
			}
			options.JSON = true
			continue
		}
		index++
		if index == len(args) {
			return ErrInvalidOptions
		}
		value := args[index]
		switch flag {
		case "--family":
			if options.BundleFamily != "" || value != "ti" && value != "policy" {
				return ErrInvalidOptions
			}
			options.BundleFamily = value
		case "--from":
			if options.BundleCommand != "install" || options.BundleSource != "" || !validInstallSource(value) {
				return ErrInvalidOptions
			}
			options.BundleSource = value
		case "--signature":
			if options.BundleCommand != "install" || options.BundleSignature != "" || !validInstallSource(value) {
				return ErrInvalidOptions
			}
			options.BundleSignature = value
		default:
			return ErrInvalidOptions
		}
	}
	if !options.JSON || options.BundleFamily == "" {
		return ErrInvalidOptions
	}
	if options.BundleCommand == "install" {
		if options.BundleSource == "" || options.BundleSignature == "" {
			return ErrInvalidOptions
		}
	} else if options.BundleSource != "" || options.BundleSignature != "" {
		return ErrInvalidOptions
	}
	return nil
}

func parsePolicyOptions(args []string, options *Options) error {
	if len(args) == 0 {
		return ErrInvalidOptions
	}
	options.PolicyCommand = args[0]
	if options.PolicyCommand != "init" && options.PolicyCommand != "pin" && options.PolicyCommand != "check" {
		return ErrInvalidOptions
	}
	for index := 1; index < len(args); index++ {
		flag := args[index]
		switch flag {
		case "--json":
			if options.PolicyCommand != "check" || options.JSON || options.Pretty {
				return ErrInvalidOptions
			}
			options.JSON = true
			continue
		case "--pretty":
			if options.PolicyCommand != "check" || options.JSON || options.Pretty {
				return ErrInvalidOptions
			}
			options.Pretty = true
			continue
		case "--policy":
			if index+1 == len(args) {
				return ErrInvalidOptions
			}
			index++
			if options.PolicyPath != "" || !validPolicyPath(args[index]) {
				return ErrInvalidOptions
			}
			options.PolicyPath = args[index]
		case "--update":
			if index+1 == len(args) {
				return ErrInvalidOptions
			}
			index++
			if options.PolicyCommand != "pin" || options.PolicyAssetID != "" || args[index] == "" || strings.ContainsRune(args[index], '\x00') {
				return ErrInvalidOptions
			}
			options.PolicyAssetID = args[index]
		default:
			return ErrInvalidOptions
		}
	}
	if options.PolicyCommand == "check" && !options.JSON && !options.Pretty {
		options.JSON = true
	}
	return nil
}

func validPolicyPath(value string) bool {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return false
	}
	if strings.HasPrefix(value, "$HOME/") {
		relative := strings.TrimPrefix(value, "$HOME/")
		return relative != "" && relative == filepath.Clean(relative) && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
	}
	return filepath.IsAbs(value) && value == filepath.Clean(value)
}

func parseScanOptions(args []string, options *Options) error {
	seenRoots := make(map[string]struct{})
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--baseline":
			if options.Baseline {
				return ErrInvalidOptions
			}
			options.Baseline = true
		case argument == "--json":
			if options.JSON {
				return ErrInvalidOptions
			}
			options.JSON = true
		case argument == "--pretty":
			if options.Pretty {
				return ErrInvalidOptions
			}
			options.Pretty = true
		case argument == "--external-probes":
			if options.ExternalProbes {
				return ErrInvalidOptions
			}
			options.ExternalProbes = true
		case argument == "--project-root":
			index++
			if index == len(args) || addProjectRoot(options, seenRoots, args[index]) != nil {
				return ErrInvalidOptions
			}
		case strings.HasPrefix(argument, "--project-root="):
			if addProjectRoot(options, seenRoots, strings.TrimPrefix(argument, "--project-root=")) != nil {
				return ErrInvalidOptions
			}
		default:
			return ErrInvalidOptions
		}
	}
	if !options.Baseline || options.JSON == options.Pretty {
		return ErrInvalidOptions
	}
	return nil
}

// parseInstallOptions accepts exactly
// `install --from <absolute path> --version <version> --sha256 <digest> --json`,
// in any flag order. Every flag is required, may appear once, and carries a
// separate value: there is no `--flag=value` form and no default for any of
// them, so an adapter cannot install something it did not name and pin. Each
// value is validated here rather than at the installer, so an unusable version
// or digest never becomes a path or a comparison.
func parseInstallOptions(args []string, options *Options) error {
	for index := 0; index < len(args); index++ {
		flag := args[index]
		if flag == "--json" {
			if options.JSON {
				return ErrInvalidOptions
			}
			options.JSON = true
			continue
		}
		index++
		if index == len(args) {
			return ErrInvalidOptions
		}
		value := args[index]
		switch flag {
		case "--from":
			if options.InstallSource != "" || !validInstallSource(value) {
				return ErrInvalidOptions
			}
			options.InstallSource = value
		case "--version":
			if options.InstallVersion != "" || !platform.ValidInstallVersion(value) {
				return ErrInvalidOptions
			}
			options.InstallVersion = value
		case "--sha256":
			if options.InstallDigest != "" || !validInstallDigest(value) {
				return ErrInvalidOptions
			}
			options.InstallDigest = value
		default:
			return ErrInvalidOptions
		}
	}
	if !options.JSON || options.InstallSource == "" || options.InstallVersion == "" || options.InstallDigest == "" {
		return ErrInvalidOptions
	}
	return nil
}

// validInstallSource accepts an absolute, already-clean path with no embedded
// NUL. Requiring the cleaned form keeps `.`, `..`, and trailing separators out
// of what is handed to the installer.
func validInstallSource(value string) bool {
	return value != "" && filepath.IsAbs(value) &&
		!strings.ContainsRune(value, '\x00') && value == filepath.Clean(value)
}

// validInstallDigest accepts only the exact shape a SHA-256 sum is published
// in, so a truncated or upper-case digest is refused here rather than becoming
// a silently weaker comparison downstream.
func validInstallDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func addProjectRoot(options *Options, seen map[string]struct{}, value string) error {
	canonical, ok := canonicalProjectRoot(value)
	if !ok {
		return ErrInvalidOptions
	}
	if _, duplicate := seen[canonical]; duplicate {
		return ErrInvalidOptions
	}
	seen[canonical] = struct{}{}
	options.ProjectRoots = append(options.ProjectRoots, value)
	return nil
}

func canonicalProjectRoot(value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", false
	}
	if value == "$HOME" {
		return value, true
	}
	if strings.HasPrefix(value, "$HOME/") {
		relative := filepath.Clean(strings.TrimPrefix(value, "$HOME/"))
		if relative == "." {
			return "$HOME", true
		}
		if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return "", false
		}
		return filepath.ToSlash(filepath.Join("$HOME", relative)), true
	}
	if !filepath.IsAbs(value) {
		return "", false
	}
	return filepath.Clean(value), true
}
