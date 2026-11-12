#!/bin/sh
# Run every PHA demo scenario in order. Requires Python 3 with the in-tree
# tlslite-ng importable (run from the repository root, or with it on PYTHONPATH).
set -e
cd "$(dirname "$0")"
for scenario in scenario1_interleave.py scenario2_empty_cert.py \
                scenario3_bad_signature.py scenario4_success_and_context.py; do
    echo "===================================================================="
    echo "RUN  $scenario"
    echo "===================================================================="
    python3 "$scenario"
    echo
done
echo "All PHA scenarios passed."
