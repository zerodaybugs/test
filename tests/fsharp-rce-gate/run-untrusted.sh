#!/bin/sh
set -eu
chmod +x tests/fsharp-rce-gate/emit-malicious-diff.sh tests/fsharp-rce-gate/hooks/pre-commit
git config diff.privileged-config.command "$PWD/tests/fsharp-rce-gate/emit-malicious-diff.sh"
printf 'changed by attacker-controlled PR code\n' > src/fsharp-rce-gate/trigger.txt
