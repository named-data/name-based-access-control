#!/usr/bin/env bash

# It's intentional not to use `set -x`, because this script explicitly prints useful information
# and should not run in trace mode.
# It's intentional not to use `set -e`, because this script wants to check all headers
# (similar to running all test cases), instead of failing at the first error.

PROJ=ndn-nac

if [[ -n $DISABLE_HEADERS_CHECK ]]; then
  echo 'Skipping headers check.'
  exit 0
fi

if has CentOS-8 $NODE_LABELS; then
  export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig
fi

CXX=${CXX:-g++}
STD=-std=c++14
CXXFLAGS="-O2 -Wall -Wno-unneeded-internal-declaration -Wno-unused-const-variable $(pkg-config --cflags libndn-cxx lib$PROJ)"
INCLUDEDIR="$(pkg-config --variable=includedir lib$PROJ)"/$PROJ

echo "Using: $CXX $STD $CXXFLAGS"

NCHECKED=0
NERRORS=0
while IFS= read -r -d '' H; do
  echo "Checking header ${H#${INCLUDEDIR}/}"
  "$CXX" -xc++ $STD $CXXFLAGS -c -o /dev/null "$H"
  [[ $? -eq 0 ]] || ((NERRORS++))
  ((NCHECKED++))
done < <(find "$INCLUDEDIR" -name '*.hpp' -type f -print0 2>/dev/null)

if [[ $NCHECKED -eq 0 ]]; then
  echo "No headers found. Is $PROJ installed?"
  exit 1
else
  echo "$NCHECKED headers checked."
fi

if [[ $NERRORS -gt 0 ]]; then
  echo "$NERRORS headers could not be compiled."
  exit 1
fi
