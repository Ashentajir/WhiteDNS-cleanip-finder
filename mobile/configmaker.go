package mobile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"whitedns-go/internal/configmaker"
)

// configMakerDir returns {dataDir}/config maker/ (created), so all config-maker
// outputs land inside the same WhiteDNS Scanner folder the app uses for results.
func configMakerDir(dataDir string) (string, error) {
	dir := filepath.Join(dataDir, "config maker")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func writeConfigMakerLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

// ConfigMakerRewrite rewrites the given proxy configs (vless/vmess/trojan/ss/
// hysteria URIs, WireGuard / AmneziaWG configs, Amnezia vpn:// links) so each
// points at one of the supplied IP:port targets. The result is written under
// {dataDir}/config maker/ and the file path is returned.
//
// Any WireGuard or AmneziaWG config among the results is additionally written
// as its own importable .conf, in a folder beside the combined text file
// sharing its name (rewritten-<stamp>.txt -> rewritten-<stamp>/wg-1.conf).
func ConfigMakerRewrite(dataDir, configsText, targetsText string) (string, error) {
	configs := configmaker.ExtractConfigs(configsText)
	if len(configs) == 0 {
		return "", fmt.Errorf("no proxy configs found in input")
	}
	targets := configmaker.ExtractTargets(targetsText)
	if len(targets) == 0 {
		return "", fmt.Errorf("no valid IP:port targets found")
	}
	out := configmaker.RewriteConfigs(configs, targets)
	dir, err := configMakerDir(dataDir)
	if err != nil {
		return "", err
	}
	stem := fmt.Sprintf("rewritten-%s", time.Now().Format("20060102-150405"))
	path := filepath.Join(dir, stem+".txt")
	if err := writeConfigMakerLines(path, out); err != nil {
		return "", err
	}
	if _, err := configmaker.WriteWireguardConfFiles(dir, stem, out); err != nil {
		return "", err
	}
	return path, nil
}

// ConfigMakerExtractIPs extracts IP:port endpoints from the given proxy configs
// / text (the reverse operation), writes them under {dataDir}/config maker/, and
// returns the output file path.
func ConfigMakerExtractIPs(dataDir, configsText string) (string, error) {
	ips := configmaker.ExtractIPs(configsText)
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP:port endpoints found")
	}
	dir, err := configMakerDir(dataDir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("extracted-ips-%s.txt", time.Now().Format("20060102-150405")))
	if err := writeConfigMakerLines(path, ips); err != nil {
		return "", err
	}
	return path, nil
}

// The three Inspect helpers below let the app show what a paste actually parses
// into before anything is written. They run the same parser the rewrite uses,
// so the count on screen is the count that will be produced — a second,
// UI-side guess at the format would drift from the engine and mislead.

// ConfigMakerCountConfigs returns how many configs the given text parses into.
func ConfigMakerCountConfigs(configsText string) int {
	return len(configmaker.ExtractConfigs(configsText))
}

// ConfigMakerCountTargets returns how many valid IP:port targets the given text
// parses into.
func ConfigMakerCountTargets(targetsText string) int {
	return len(configmaker.ExtractTargets(targetsText))
}

// ConfigMakerSummarizeConfigs returns a per-protocol breakdown of the configs
// in the given text, e.g. "2 vless  |  1 AmneziaWG", or "" when none parse.
func ConfigMakerSummarizeConfigs(configsText string) string {
	return configmaker.FormatTally(configmaker.ExtractConfigs(configsText))
}
