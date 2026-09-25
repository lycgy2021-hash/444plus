package config

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopoc/internal/httpx"
	"gopoc/internal/model"

	"gopkg.in/yaml.v3"
)

type Config struct {
	HTTP      httpx.Options `yaml:"http"`
	Allowlist []string      `yaml:"allowlist"`
	Active    struct {
		Enabled bool               `yaml:"enabled"`
		Canary  model.CanaryConfig `yaml:"canary"`
	} `yaml:"active"`
}

func Defaults() Config {
	c := Config{HTTP: httpx.Defaults()}
	c.Active.Canary.AliasPath = "/canary-alias/"
	c.Active.Canary.TraversalDepth = 4
	return c
}

func Load(path string) (Config, error) {
	c := Defaults()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return c, fmt.Errorf("configuration must be a regular file no larger than 1 MiB")
	}
	d := yaml.NewDecoder(io.LimitReader(f, 1<<20))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("reading configuration: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return c, fmt.Errorf("configuration must contain exactly one YAML document")
	}
	return c, nil
}

func (c Config) Validate(mode model.Mode) error {
	if err := c.HTTP.Validate(); err != nil {
		return err
	}
	switch mode {
	case model.ModeActiveCanary:
		if !c.Active.Enabled {
			return fmt.Errorf("active-canary mode requires active.enabled: true in the configuration")
		}
		if err := c.Active.Canary.Validate(); err != nil {
			return err
		}
		if int64(len(c.Active.Canary.Expected)+2) > c.HTTP.MaxBodySize {
			return fmt.Errorf("max_body_size must accommodate the complete expected canary and newline")
		}
	case model.ModePassive, model.ModeActiveProbe:
	default:
		return fmt.Errorf("mode must be passive, active-canary or active-probe")
	}
	return nil
}
