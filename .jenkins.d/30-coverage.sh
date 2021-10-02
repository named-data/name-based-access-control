#!/usr/bin/env bash
set -ex

if [[ $JOB_NAME == *"code-coverage" ]]; then
    # Generate an XML report (Cobertura format)
    gcovr --object-directory=build \
          --output=build/coverage.xml \
          --exclude="$PWD/tests" \
          --root=. \
          --xml

    # Generate a detailed HTML report using lcov
    lcov --quiet \
         --capture \
         --directory . \
         --exclude "$PWD/tests/*" \
         --no-external \
         --rc lcov_branch_coverage=1 \
         --output-file build/coverage.info

    genhtml --branch-coverage \
            --demangle-cpp \
            --legend \
            --output-directory build/lcov \
            --title "ndn-nac unit tests" \
            build/coverage.info
fi
