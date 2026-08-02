Ephemeral encrypted local-integration runner trigger.

The workflow publishes a one-time recipient certificate, waits for a CMS-encrypted payload on the pull-request head branch, executes it without exposing plaintext output, and returns only a CMS-encrypted result bundle.

No payload is stored in this trigger file.
