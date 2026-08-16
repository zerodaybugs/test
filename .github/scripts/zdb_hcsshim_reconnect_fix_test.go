//go:build linux

package bridge

import (
    "fmt"
    "io"
    "testing"
    "time"

    "github.com/Microsoft/hcsshim/internal/guest/prot"
    "github.com/sirupsen/logrus"
)

type zdbFixedReadResult struct {
    header *prot.MessageHeader
    body   []byte
    err    error
}

func zdbFixedReadWithTimeout(r io.Reader, timeout time.Duration) zdbFixedReadResult {
    ch := make(chan zdbFixedReadResult, 1)
    go func() {
        h, body, err := serverRead(r)
        ch <- zdbFixedReadResult{header: h, body: body, err: err}
    }()
    select {
    case result := <-ch:
        return result
    case <-time.After(timeout):
        return zdbFixedReadResult{err: fmt.Errorf("timed out waiting for bridge response")}
    }
}

func TestZDBBridgeReconnectPreservesSequentialEpochBoundary(t *testing.T) {
    logrus.SetOutput(io.Discard)

    firstEntered := make(chan struct{})
    releaseFirst := make(chan struct{})
    secondEntered := make(chan struct{})
    releaseSecond := make(chan struct{})

    mux := NewBridgeMux()
    mux.HandleFunc(prot.ComputeSystemCreateV1, prot.PvInvalid,
        func(_ *Request) (RequestResponse, error) {
            close(firstEntered)
            <-releaseFirst
            return &prot.MessageResponseBase{Result: 101}, nil
        })
    mux.HandleFunc(prot.ComputeSystemModifySettingsV1, prot.PvInvalid,
        func(_ *Request) (RequestResponse, error) {
            close(secondEntered)
            <-releaseSecond
            return &prot.MessageResponseBase{Result: 202}, nil
        })

    b := &Bridge{Handler: mux, Sequential: true}

    first := newLoopbackConnection()
    defer first.close()
    serveFirst := make(chan error, 1)
    go func() { serveFirst <- b.ListenAndServe(first.SRead(), first.SWrite()) }()

    const oldID prot.SequenceID = 1001
    if err := serverSend(first.CWrite(), prot.ComputeSystemCreateV1, oldID, nil); err != nil {
        t.Fatalf("send first request: %v", err)
    }
    select {
    case <-firstEntered:
    case <-time.After(2 * time.Second):
        t.Fatal("first mutating request did not enter handler")
    }

    if err := first.CWrite().Close(); err != nil {
        t.Fatalf("disconnect first host transport: %v", err)
    }
    select {
    case <-serveFirst:
    case <-time.After(2 * time.Second):
        t.Fatal("first ListenAndServe did not return after disconnect")
    }

    second := newLoopbackConnection()
    defer second.close()
    serveSecond := make(chan error, 1)
    go func() { serveSecond <- b.ListenAndServe(second.SRead(), second.SWrite()) }()

    const newID prot.SequenceID = 2002
    if err := serverSend(second.CWrite(), prot.ComputeSystemModifySettingsV1, newID, nil); err != nil {
        t.Fatalf("send second request: %v", err)
    }

    select {
    case <-secondEntered:
        t.Fatal("second mutating request overlapped the old connection epoch")
    case <-time.After(150 * time.Millisecond):
        fmt.Println("ZDB_FIXED_CROSS_CONNECTION_OVERLAP_BLOCKED=true")
    }

    close(releaseFirst)

    select {
    case <-secondEntered:
        fmt.Println("ZDB_FIXED_SECOND_REQUEST_ENTERED_AFTER_OLD_COMPLETION=true")
    case <-time.After(2 * time.Second):
        t.Fatal("second request did not enter after old request completed")
    }

    close(releaseSecond)
    current := zdbFixedReadWithTimeout(second.CRead(), 2*time.Second)
    if current.err != nil {
        t.Fatalf("read current response: %v", current.err)
    }
    if current.header.Type != prot.ComputeSystemResponseModifySettingsV1 || current.header.ID != newID {
        t.Fatalf("stale response crossed connection epoch: got type=%v id=%d; want type=%v id=%d",
            current.header.Type, current.header.ID,
            prot.ComputeSystemResponseModifySettingsV1, newID)
    }
    fmt.Println("ZDB_FIXED_OLD_RESPONSE_DROPPED=true")

    if err := second.CWrite().Close(); err != nil {
        t.Fatalf("disconnect second host transport: %v", err)
    }
    select {
    case <-serveSecond:
    case <-time.After(2 * time.Second):
        t.Fatal("second ListenAndServe did not return")
    }

    fmt.Println("ZDB_PATCHED_RECONNECT_EPOCH_INVARIANT=PASS")
}
