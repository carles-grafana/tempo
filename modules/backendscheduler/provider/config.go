package provider

import (
	"flag"
	"fmt"

	"github.com/grafana/tempo/pkg/util"
)

// Config contains configuration for all providers
type Config struct {
	Retention  RetentionConfig  `yaml:"retention"`
	Compaction CompactionConfig `yaml:"compaction"`
}

func (cfg *Config) RegisterFlagsAndApplyDefaults(prefix string, f *flag.FlagSet) {
	cfg.Retention.RegisterFlagsAndApplyDefaults(util.PrefixConfig(prefix, "work"), f)
	cfg.Compaction.RegisterFlagsAndApplyDefaults(util.PrefixConfig(prefix, "work"), f)
}

func ValidateConfig(cfg *Config) error {
	if cfg.Compaction.MaxJobsPerTenant <= 0 {
		return fmt.Errorf("max_jobs_per_tenant must be greater than 0")
	}

	return nil
}
