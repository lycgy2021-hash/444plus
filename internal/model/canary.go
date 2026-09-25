package model

import (
	"fmt"
	"strings"
)

type CanaryConfig struct {
	AliasPath      string `yaml:"alias_path"`
	TraversalDepth int    `yaml:"traversal_depth"`
	FilePath       string `yaml:"file_path"`
	Expected       string `yaml:"expected"`
}

func (c CanaryConfig) Validate() error {
	if len(c.Expected) < 8 || len(c.Expected) > 4096 || strings.TrimSpace(c.Expected) != c.Expected {
		return fmt.Errorf("canary.expected must have 8–4096 bytes and no leading/trailing whitespace")
	}
	if c.TraversalDepth < 1 || c.TraversalDepth > 16 {
		return fmt.Errorf("canary.traversal_depth must be between 1 and 16")
	}
	if !strings.HasPrefix(c.AliasPath, "/") || c.AliasPath == "/" || !strings.HasSuffix(c.AliasPath, "/") {
		return fmt.Errorf("canary.alias_path must be an absolute directory URL path, e.g. /canary-alias/")
	}
	if !strings.HasPrefix(c.FilePath, "/") || strings.HasSuffix(c.FilePath, "/") {
		return fmt.Errorf("canary.file_path must be an absolute server filesystem file path")
	}
	for _, raw := range []string{c.AliasPath, c.FilePath} {
		for _, b := range []byte(raw) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("/._-", rune(b))) {
				return fmt.Errorf("canary paths may contain only ASCII letters, digits, /, ., _, -")
			}
		}
		for _, segment := range strings.Split(strings.Trim(raw, "/"), "/") {
			if segment == "" || segment == "." || segment == ".." {
				return fmt.Errorf("canary paths must not contain empty, . or .. segments")
			}
		}
	}
	return nil
}
