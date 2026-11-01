#!/bin/sh
# Copy the runtime package, rules and sample logs from the private repository.
# Only what the browser needs is published; tests, benchmarks and history stay private.
set -eu
SRC="${1:-../log-threat-detector}"
HERE="$(cd "$(dirname "$0")" && pwd)"
rm -rf "$HERE/py/logdetect" "$HERE/py/rules" "$HERE/samples"
mkdir -p "$HERE/py/logdetect" "$HERE/py/rules" "$HERE/samples"
for f in __init__ models parsers rules engine reports; do
  cp "$SRC/src/logdetect/$f.py" "$HERE/py/logdetect/$f.py"
done
cp "$SRC"/rules/*.yml "$HERE/py/rules/"
cp "$SRC/samples/auth.log" "$SRC/samples/access.log" "$HERE/samples/"
git -C "$SRC" rev-parse --short HEAD > "$HERE/py/SOURCE_REV"
echo "synced from $(cat "$HERE/py/SOURCE_REV")"
