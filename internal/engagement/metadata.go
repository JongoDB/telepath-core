package engagement

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/fsc/telepath-core/pkg/schema"
)

// readEngagementYAML parses engagement.yaml at path.
func readEngagementYAML(path string) (schema.Engagement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return schema.Engagement{}, err
	}
	var e schema.Engagement
	if err := yaml.Unmarshal(data, &e); err != nil {
		return schema.Engagement{}, fmt.Errorf("engagement: parse %s: %w", path, err)
	}
	return e, nil
}

// writeEngagementYAML serializes e as YAML and writes it atomically
// (write-temp-then-rename) to path. Parent directory is created if needed.
func writeEngagementYAML(path string, e schema.Engagement) error {
	data, err := yaml.Marshal(e)
	if err != nil {
		return fmt.Errorf("engagement: marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("engagement: mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("engagement: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("engagement: rename %s: %w", path, err)
	}
	return nil
}
