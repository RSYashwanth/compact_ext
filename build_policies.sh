#!/bin/bash
set -eu -o pipefail

if ! uname -r | grep -q "compact-ext"; then
	echo "This script is intended to be run on a compact_ext kernel."
	echo "Please switch to the compact_ext kernel and try again."
	exit 1
fi

SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname $SCRIPT_PATH)
POLICY_PATH="$BASE_DIR/policies"

make -C "$POLICY_PATH" -j
