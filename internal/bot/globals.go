package bot

import (
	"sync"
)

var (
	globalMu       sync.RWMutex
	globalDetector *Detector
)

// InitGlobals lazily initializes the bot detection globals.
func InitGlobals() {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalDetector != nil {
		return
	}
	globalDetector = NewDetector()
}

func getGlobalDetector() *Detector {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalDetector
}

// SetDetector allows tests to inject a mock detector.
func SetDetector(d *Detector) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalDetector = d
}
