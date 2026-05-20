#!/usr/bin/env bash
# ZAC Phase 4 — end-to-end demo.
#
# Drives the user-facing `zac` binary through the full pipeline:
# build → version → inspect → hash → prove → verify → negative-case verify.
# Every step prints a one-line OK, and the final negative case asserts that
# `zac verify` returns exit code 2 (proof rejected) — not 1 (crash) — when
# the proof block is tampered with.
#
# Run with:
#   bash scripts/e2e_demo.sh
#
# Set ZAC_KEEP_TMP=1 to leave /tmp/{out,bad}.zacp on disk for hex-dump
# inspection after the run.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "==[1/7]==  build release binary"
cargo build --release -q --bin zac

ZAC=./target/release/zac

echo "==[2/7]==  zac --version"
$ZAC --version

echo "==[3/7]==  zac inspect fixtures/multiplier.zac"
# Temporarily disable pipefail: `head` closes the pipe early on purpose so
# we can show just the top of the dump, which makes `zac` exit on SIGPIPE
# (141). That's the intended Unix behaviour, not a failure.
set +o pipefail
$ZAC inspect fixtures/multiplier.zac | head -25
set -o pipefail

echo "==[4/7]==  zac inspect fixtures/multiplier.zacp"
set +o pipefail
$ZAC inspect fixtures/multiplier.zacp | head -15
set -o pipefail

echo "==[5/7]==  zac hash fixtures/multiplier.zac"
$ZAC hash fixtures/multiplier.zac

echo "==[6/7]==  zac prove (native, deterministic seed) -> /tmp/out.zacp"
rm -f /tmp/out.zacp
$ZAC prove fixtures/multiplier.zac fixtures/multiplier.zkey fixtures/multiplier.wtns -o /tmp/out.zacp

echo "==[7/7]==  zac verify fixtures/multiplier.zac /tmp/out.zacp"
$ZAC verify fixtures/multiplier.zac /tmp/out.zacp

echo
echo "==  negative case: corrupt the proof, verify must exit 2"
cp /tmp/out.zacp /tmp/bad.zacp
# Flip a byte inside the proof block. Offset 0x60 sits in the middle of
# pi_a — a single bit flip there is enough to make the pairing reject
# without falling foul of any structural check.
printf '\xff' | dd of=/tmp/bad.zacp bs=1 seek=96 count=1 conv=notrunc 2>/dev/null
set +e
$ZAC verify fixtures/multiplier.zac /tmp/bad.zacp
rc=$?
set -e
if [ $rc -ne 2 ]; then
  echo "FAIL: expected exit 2, got $rc"
  exit 1
fi
echo "  -> got expected exit 2 (verify rejected)"

echo
echo "==  no-overwrite regression (Phase 5): prove must refuse existing output"
# `/tmp/out.zacp` still exists at this point (we only delete it at the very
# end if ZAC_KEEP_TMP is unset). Reuse it as a pre-existing target.
set +e
$ZAC prove fixtures/multiplier.zac fixtures/multiplier.zkey fixtures/multiplier.wtns -o /tmp/out.zacp >/dev/null 2>&1
rc=$?
set -e
if [ $rc -ne 3 ]; then
  echo "FAIL: prove (refuse-overwrite) expected exit 3, got $rc"
  exit 1
fi
echo "  -> prove refuse-overwrite: got expected exit 3"

set +e
$ZAC prove fixtures/multiplier.zac fixtures/multiplier.zkey fixtures/multiplier.wtns -o /tmp/out.zacp --force >/dev/null 2>&1
rc=$?
set -e
if [ $rc -ne 0 ]; then
  echo "FAIL: prove --force expected exit 0, got $rc"
  exit 1
fi
echo "  -> prove --force overwrite: got expected exit 0"

echo
echo "==  no-overwrite regression (Phase 5): pack must refuse existing output"
# Pack into a path that already exists (the existing fixture).
set +e
$ZAC pack fixtures/multiplier.zkey fixtures/multiplier.r1cs -o fixtures/multiplier.zac >/dev/null 2>&1
rc=$?
set -e
if [ $rc -ne 3 ]; then
  echo "FAIL: pack (refuse-overwrite) expected exit 3, got $rc"
  exit 1
fi
echo "  -> pack refuse-overwrite: got expected exit 3"

# --force pack into a temp path (avoid disturbing fixtures/multiplier.zac
# which other tools/tests assume is byte-stable).
rm -f /tmp/pack-force.zac
$ZAC pack fixtures/multiplier.zkey fixtures/multiplier.r1cs -o /tmp/pack-force.zac >/dev/null 2>&1
# Now force-overwrite the same path.
set +e
$ZAC pack fixtures/multiplier.zkey fixtures/multiplier.r1cs -o /tmp/pack-force.zac --force >/dev/null 2>&1
rc=$?
set -e
if [ $rc -ne 0 ]; then
  echo "FAIL: pack --force expected exit 0, got $rc"
  exit 1
fi
echo "  -> pack --force overwrite: got expected exit 0"

if [ -z "${ZAC_KEEP_TMP:-}" ]; then
  rm -f /tmp/out.zacp /tmp/bad.zacp /tmp/pack-force.zac
fi

echo
echo "==  E2E DEMO: ALL OK"
