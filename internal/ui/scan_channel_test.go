package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// A scan closes its message channel as soon as it returns, but the health
// monitor is stopped by a context cancel that does not wait for its goroutine,
// so a log line can still arrive afterwards. That must not take down the TUI.
func TestSendScanMsgSurvivesClosedChannel(t *testing.T) {
	ch := make(chan tea.Msg, 1)
	close(ch)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a late scanner log panicked the UI: %v", r)
		}
	}()
	sendScanMsg(ch, logMsg{text: "late line from the health monitor"})
}

func TestSendScanMsgDeliversWhenOpen(t *testing.T) {
	ch := make(chan tea.Msg, 1)
	sendScanMsg(ch, logMsg{text: "hello"})
	select {
	case got := <-ch:
		if lm, ok := got.(logMsg); !ok || lm.text != "hello" {
			t.Fatalf("unexpected message: %#v", got)
		}
	default:
		t.Fatal("message was not delivered")
	}
}
