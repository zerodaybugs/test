#!/bin/sh
set -eu
git config diff.privileged-config.command "sh $PWD/tests/fsharp-rce-gate/emit-malicious-diff.sh"
printf 'changed by attacker-controlled PR code\n' > src/fsharp-rce-gate/trigger.txt
