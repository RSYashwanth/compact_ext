#!/bin/bash
set -u

TEST_DIR=$(dirname "$(realpath "$0")")
NODE_ID=${1:-0}
TESTS=(wrong_type_attach double_attach)
failed=0

if [[ $EUID -ne 0 ]]; then
	echo "run_tests.sh must be run as root"
	exit 1
fi

for t in "${TESTS[@]}"; do
	echo "--- $t"
	if [[ ! -x "$TEST_DIR/$t.out" ]]; then
		echo "$TEST_DIR/$t.out not found; run make in policies/"
		status=1
	else
		"$TEST_DIR/$t.out" "$NODE_ID"
		status=$?
	fi

	if [[ $status -eq 0 ]]; then
		echo "PASS $t"
	else
		echo "FAIL $t"
		failed=$((failed + 1))
	fi
done

echo "$((${#TESTS[@]} - failed))/${#TESTS[@]} tests passed"
[[ $failed -eq 0 ]]
