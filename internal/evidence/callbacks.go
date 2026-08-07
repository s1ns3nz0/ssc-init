package evidence

import "context"

const maxEvidenceCallbacks = 4

// callbackLimiter caps detached, cancellation-isolated extension callbacks.
// A slot is held until the callback actually returns, even after its caller's
// target context has expired.
type callbackLimiter struct {
	slots chan struct{}
}

func newCallbackLimiter(capacity int) *callbackLimiter {
	if capacity <= 0 || capacity > maxEvidenceCallbacks {
		capacity = maxEvidenceCallbacks
	}
	return &callbackLimiter{slots: make(chan struct{}, capacity)}
}

func (limiter *callbackLimiter) acquire(ctx context.Context) bool {
	if limiter == nil {
		return false
	}
	select {
	case limiter.slots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (limiter *callbackLimiter) release() {
	if limiter != nil {
		<-limiter.slots
	}
}

var processCallbackLimiter = newCallbackLimiter(maxEvidenceCallbacks)
