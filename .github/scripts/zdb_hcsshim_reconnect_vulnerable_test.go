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

type zdbVulnerableReadResult struct {
    header *prot.MessageHeader
    body   []byte
    err    error
}

func zdbVulnerableReadWithTimeout(r io.Reader, timeout time.Duration) zdbVulnerableReadResult {
    ch := make(chan zdbVulnerableReadResult, 1)
    go func() {
        h, body, err := serverRead(r)
        ch <- zdbVulnerableReadResult{header: h, body: body, err: err}
    }()
    select {
    case result := <-ch:
        return result
    case <-time.After(timeout):
        return zdbVulnerableReadResult{err: fmt.Errorf("timed out waiting for bridge response")}
    }
}

func TestZDBBridgeSequentialModeIsBypassedAcrossReconnect(t *testing.T) {
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
        fmt.Println("ZDB_CROSS_CONNECTION_MUTATING_OVERLAP=true")
    case <-time.After(750 * time.Millisecond):
        t.Fatal("new mutating request was serialized behind the in-flight old-connection request")
    }

    close(releaseFirst)
    stale := zdbVulnerableReadWithTimeout(second.CRead(), 2*time.Second)
    if stale.err != nil {
        t.Fatalf("read old-epoch response on new connection: %v", stale.err)
    }
    if stale.header.Type != prot.ComputeSystemResponseCreateV1 || stale.header.ID != oldID {
        t.Fatalf("expected stale create response id=%d on new connection, got type=%v id=%d",
            oldID, stale.header.Type, stale.header.ID)
    }
    fmt.Printf("ZDB_OLD_RESPONSE_DELIVERED_ON_NEW_CONNECTION=true old_id=%d\n", oldID)

    close(releaseSecond)
    current := zdbVulnerableReadWithTimeout(second.CRead(), 2*time.Second)
    if current.err != nil {
        t.Fatalf("read current response: %v", current.err)
    }
    if current.header.Type != prot.ComputeSystemResponseModifySettingsV1 || current.header.ID != newID {
        t.Fatalf("expected modify response id=%d, got type=%v id=%d",
            newID, current.header.Type, current.header.ID)
    }

    if err := second.CWrite().Close(); err != nil {
        t.Fatalf("disconnect second host transport: %v", err)
    }
    select {
    case <-serveSecond:
    case <-time.After(2 * time.Second):
        t.Fatal("second ListenAndServe did not return")
    }

    fmt.Println("ZDB_RECONNECT_EPOCH_BYPASS=PASS")
}
