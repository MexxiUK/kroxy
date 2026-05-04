package metrics

import (
	"sync/atomic"
)

var (
	requestsTotal    int64
	authSuccessTotal int64
	authFailureTotal int64
)

// IncRequests increments the total request counter.
func IncRequests() {
	atomic.AddInt64(&requestsTotal, 1)
}

// RequestsTotal returns the total number of requests processed.
func RequestsTotal() int64 {
	return atomic.LoadInt64(&requestsTotal)
}

// IncAuthSuccess increments successful auth attempts.
func IncAuthSuccess() {
	atomic.AddInt64(&authSuccessTotal, 1)
}

// IncAuthFailure increments failed auth attempts.
func IncAuthFailure() {
	atomic.AddInt64(&authFailureTotal, 1)
}

// AuthSuccessTotal returns successful auth count.
func AuthSuccessTotal() int64 {
	return atomic.LoadInt64(&authSuccessTotal)
}

// AuthFailureTotal returns failed auth count.
func AuthFailureTotal() int64 {
	return atomic.LoadInt64(&authFailureTotal)
}
