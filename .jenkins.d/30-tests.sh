#!/usr/bin/env bash
set -x
set -e

# Prepare environment
sudo rm -Rf ~/.ndn

# Run unit tests
if [[ -n "$XUNIT" ]]; then
    ./build/unit-tests --log_format=XML --log_sink=build/xunit-report.xml --log_level=all --report_level=no
else
    ./build/unit-tests -l test_suite
fi
