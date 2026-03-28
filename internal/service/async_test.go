package service

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/osama1998h/uniauth/internal/testutil"
)

func TestAsyncDispatcherCapsConcurrency(t *testing.T) {
	const workers = 4

	started := make(chan struct{}, workers)
	release := make(chan struct{})
	var current atomic.Int32
	var maxConcurrent atomic.Int32

	dispatcher := newAsyncDispatcher("test", testutil.DiscardLogger(), 32, workers, func(_ int) {
		concurrency := current.Add(1)
		for {
			maxSeen := maxConcurrent.Load()
			if concurrency <= maxSeen || maxConcurrent.CompareAndSwap(maxSeen, concurrency) {
				break
			}
		}
		started <- struct{}{}
		<-release
		current.Add(-1)
	})

	for i := 0; i < 16; i++ {
		dispatcher.Enqueue(i)
	}

	for i := 0; i < workers; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for workers to start")
		}
	}

	if got := maxConcurrent.Load(); got > workers {
		t.Fatalf("max concurrency = %d, want <= %d", got, workers)
	}

	close(release)
}

func TestAsyncDispatcherDropsWithoutBlockingWhenQueueIsFull(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	dispatcher := newAsyncDispatcher("test", testutil.DiscardLogger(), 1, 1, func(_ int) {
		started <- struct{}{}
		<-release
	})

	dispatcher.Enqueue(1)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker to start")
	}

	dispatcher.Enqueue(2)

	start := time.Now()
	for i := 0; i < 1000; i++ {
		dispatcher.Enqueue(i + 3)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("enqueue took %s with full queue, want < 50ms", elapsed)
	}

	close(release)
}
