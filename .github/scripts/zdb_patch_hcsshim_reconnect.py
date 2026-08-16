from pathlib import Path

path = Path("repo/internal/guest/bridge/bridge.go")
text = path.read_text()

old = """\t// pendingNotifications holds container exit notifications that arrived
\t// while the bridge was disconnected. They are drained when ListenAndServe
\t// reconnects.
\tpendingNotifications []*prot.ContainerNotification
}"""
new = """\t// pendingNotifications holds container exit notifications that arrived
\t// while the bridge was disconnected. They are drained when ListenAndServe
\t// reconnects.
\tpendingNotifications []*prot.ContainerNotification

\t// sequentialMu serializes mutating request processing across transport
\t// connection epochs. A reconnect must not create a second independent
\t// sequential queue while a request from the previous connection is active.
\tsequentialMu sync.Mutex
}"""
assert old in text
text = text.replace(old, new, 1)

old = """\trequestChan := make(chan *Request)
\trequestErrChan := make(chan error)
\tb.responseChan = make(chan bridgeResponse)
\tresponseErrChan := make(chan error)
\tb.quitChan = make(chan bool)"""
new = """\trequestChan := make(chan *Request)
\trequestErrChan := make(chan error)
\tresponseChan := make(chan bridgeResponse)
\tb.responseChan = responseChan
\tresponseErrChan := make(chan error)
\tb.quitChan = make(chan bool)
\tsessionDone := make(chan struct{})"""
assert old in text
text = text.replace(old, new, 1)

old = """\tdefer b.disconnectNotifications()
\tdefer close(b.quitChan)

\tif b.Sequential {"""
new = """\tdefer b.disconnectNotifications()
\tdefer close(b.quitChan)
\t// Close this before any old request handler can publish after reconnect.
\tdefer close(sessionDone)

\tif b.Sequential {"""
assert old in text
text = text.replace(old, new, 1)

old = """\t\t\tbr.response = resp
\t\t\tb.responseChan <- br
\t\t}"""
new = """\t\t\tbr.response = resp
\t\t\t// Bind the response to the connection epoch that accepted the
\t\t\t// request. If that epoch has ended, drop the response rather than
\t\t\t// publishing it through a later connection's mutable Bridge field.
\t\t\tselect {
\t\t\tcase responseChan <- br:
\t\t\tcase <-sessionDone:
\t\t\t}
\t\t}"""
assert old in text
text = text.replace(old, new, 1)

old = """\t\tfor req := range requestChan {
\t\t\tif b.Sequential && !alwaysAsync(req.Header.Type) {
\t\t\t\t// This will log warn after 5 seconds if the request is still
\t\t\t\t// being processed,
\t\t\t\trunSequentialRequest(req, doRequest)
\t\t\t} else {
\t\t\t\tgo doRequest(req)
\t\t\t}
\t\t}
\t}()
\t// Process each bridge response sync. This channel is for request/response and publish workflows.
\tgo func() {
\t\tvar resperr error
\t\tfor resp := range b.responseChan {"""
new = """\t\tfor req := range requestChan {
\t\t\tif b.Sequential && !alwaysAsync(req.Header.Type) {
\t\t\t\t// Serialize across the lifetime of the Bridge, including
\t\t\t\t// reconnects, rather than only within this requestChan.
\t\t\t\tb.sequentialMu.Lock()
\t\t\t\trunSequentialRequest(req, doRequest)
\t\t\t\tb.sequentialMu.Unlock()
\t\t\t} else {
\t\t\t\tgo doRequest(req)
\t\t\t}
\t\t}
\t}()
\t// Bind the response writer to this connection's channel. Do not lazily
\t// dereference b.responseChan after a reconnect.
\tgo func() {
\t\tvar resperr error
\t\tfor resp := range responseChan {"""
assert old in text
text = text.replace(old, new, 1)

path.write_text(text)
