package scanner

import (
	"sync"
	"testing"
)

// The UI attaches a log sink when a scan starts and clears it when the scan
// ends, while scan workers and the health monitor are still logging. Run that
// shape under -race: an unguarded func field reports a data race here, and a
// "check != nil then call" reader can also observe the clear in between and
// call a nil func.
func TestCallbacksSurviveConcurrentAttachAndClear(t *testing.T) {
	s := NewScanner(nil)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.logf("worker line\n")
					s.reportProxyProgress(1, 2, 0, "1.2.3.4:80", 1)
				}
			}
		}()
	}

	for i := 0; i < 20000; i++ {
		s.SetLogCallback(func(string) {})
		s.SetProxyProgressCallback(func(int, int, int, string, int) {})
		s.SetLogCallback(nil)
		s.SetProxyProgressCallback(nil)
	}
	close(stop)
	wg.Wait()
}
