package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

type runFunc func(context.Context) error

func (f runFunc) Run(ctx context.Context) error { return f(ctx) }

func TestSelectedLists(t *testing.T) {
	lists, names, err := selectedLists("mw-4b,se-4b,uws-4b")
	if err != nil || len(lists) != 4 || len(names) != 3 || lists[3].Name != "gc-32b" || lists[3].HashLength != 32 {
		t.Fatalf("%v %v %v", lists, names, err)
	}
	for _, s := range []string{"", "mw-4b,mw-4b", "unknown", "gc-32b"} {
		if _, _, err := selectedLists(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestServeLifecycle(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		done := make(chan error, 1)
		failure := errors.New("initialization failed")
		updater := runFunc(func(ctx context.Context) error {
			close(started)
			if fatal {
				return failure
			}
			<-ctx.Done()
			return ctx.Err()
		})
		go func() { done <- serve(ctx, listener, http.NotFoundHandler(), updater) }()
		<-started
		if !fatal {
			client := &http.Client{Timeout: time.Second}
			response, err := client.Get("http://" + listener.Addr().String() + "/test")
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 404 {
				t.Fatal(response.StatusCode)
			}
			cancel()
		}
		select {
		case err := <-done:
			if fatal && !errors.Is(err, failure) || !fatal && err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("shutdown hung")
		}
		cancel()
	}
}
