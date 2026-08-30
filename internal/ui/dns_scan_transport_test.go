package ui

import "testing"

func TestDNSPortPresetsExposeTrueSingleTransportModes(t *testing.T) {
	found := map[string]bool{}
	for _, preset := range dnsPortPresets {
		if len(preset.ports) == 1 && preset.ports[0] == 53 {
			found[preset.protocol] = true
		}
	}
	for _, protocol := range []string{"udp", "tcp", "both"} {
		if !found[protocol] {
			t.Errorf("desktop DNS picker is missing %q-only port 53 mode", protocol)
		}
	}
}

func TestDNSPortPresetProtocolsAreAcceptedByEngine(t *testing.T) {
	for _, preset := range dnsPortPresets {
		switch preset.protocol {
		case "udp", "tcp", "both", "all":
		default:
			t.Errorf("UI preset %q passes unsupported engine protocol %q", preset.label, preset.protocol)
		}
	}
}

func TestDNSDepthPresetsExposeFastAndFullModes(t *testing.T) {
	found := map[string]bool{}
	for _, preset := range dnsDepthPresets {
		found[preset.depth] = true
	}
	for _, depth := range []string{"fast", "full"} {
		if !found[depth] {
			t.Errorf("desktop DNS picker is missing %q scan depth", depth)
		}
	}
}
