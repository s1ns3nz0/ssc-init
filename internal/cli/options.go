package cli

import (
	"errors"
	"path/filepath"
	"strings"
)

// ErrInvalidOptions is intentionally value-free so callers never echo a
// supplied path or flag value when reporting invalid command arguments.
var ErrInvalidOptions = errors.New("invalid command arguments")

// Options is the fully parsed command line accepted by SSC Init.
type Options struct {
	Command        string
	JSON           bool
	Baseline       bool
	ExternalProbes bool
	ProjectRoots   []string
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
	case "doctor", "status", "version":
		if len(args) != 2 || args[1] != "--json" {
			return Options{}, ErrInvalidOptions
		}
		options.JSON = true
	default:
		return Options{}, ErrInvalidOptions
	}
	return options, nil
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
	if !options.Baseline || !options.JSON {
		return ErrInvalidOptions
	}
	return nil
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
