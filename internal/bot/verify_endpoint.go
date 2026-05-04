package bot

import "net/http"

// VerifyEndpoint wraps ChallengeManager.HandleVerify as a standard http.Handler.
type VerifyEndpoint struct{}

func (v *VerifyEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cm := getGlobalChallengeManager()
	if cm == nil {
		http.Error(w, "Bot protection not initialized", http.StatusServiceUnavailable)
		return
	}
	cm.HandleVerify(w, r, getGlobalSecret())
}

// NewVerifyEndpoint creates the challenge verification handler.
func NewVerifyEndpoint() http.Handler {
	return &VerifyEndpoint{}
}
