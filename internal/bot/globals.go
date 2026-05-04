package bot

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"sync"
)

var (
	globalMu               sync.RWMutex
	globalDetector         *Detector
	globalCache            *IPChallengeCache
	globalChallengeManager *ChallengeManager
	globalSecret           []byte
)

// InitGlobals lazily initializes the bot detection globals.
func InitGlobals(secret string) {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalDetector != nil {
		return
	}
	globalDetector = NewDetector()
	globalCache = NewIPChallengeCache()
	if secret != "" {
		globalSecret = []byte(secret)
	} else {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("FATAL: bot detection crypto/rand failed: %v", err)
		}
		globalSecret = b
		log.Println("WARNING: Bot detection secret auto-generated. Sessions will be invalidated on restart. Set KROXY_BOT_SECRET for persistence.")
	}
	globalChallengeManager = NewChallengeManager(string(globalSecret))
}

func getGlobalDetector() *Detector {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalDetector
}

func getGlobalCache() *IPChallengeCache {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalCache
}

func getGlobalChallengeManager() *ChallengeManager {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalChallengeManager
}

func getGlobalSecret() []byte {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalSecret
}

// SetSecret updates the global secret (used during app startup).
func SetSecret(secret string) {
	globalMu.Lock()
	defer globalMu.Unlock()
	if secret != "" {
		globalSecret = []byte(secret)
		globalChallengeManager = NewChallengeManager(secret)
	}
}

// SetDetector allows tests to inject a mock detector.
func SetDetector(d *Detector) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalDetector = d
}

// HexSecret returns the current secret as a hex string for persistence/debug.
func HexSecret() string {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return hex.EncodeToString(globalSecret)
}
