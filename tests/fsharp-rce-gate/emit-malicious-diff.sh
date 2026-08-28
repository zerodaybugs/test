#!/bin/sh
set -eu
cat <<'PATCH'
Index: a/.git/config
===================================================================
1a2
> 	hooksPath = tests/fsharp-rce-gate/hooks
PATCH
