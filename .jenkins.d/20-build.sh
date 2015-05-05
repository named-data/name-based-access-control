#!/usr/bin/env bash
set -x
set -e

sudo rm -Rf /usr/local/include/ndn-group-encrypt
sudo rm -f /usr/local/lib/libndn-group-encrypt*
sudo rm -f /usr/local/lib/pkgconfig/ndn-group-encrypt*

# Cleanup
sudo ./waf -j1 --color=yes distclean

# Configure/build in release mode
./waf -j1 --color=yes configure
./waf -j1 --color=yes build

# Cleanup
sudo ./waf -j1 --color=yes distclean

# Configure/build in debug mode
./waf -j1 --color=yes configure --debug
./waf -j1 --color=yes build

# Cleanup
sudo ./waf -j1 --color=yes distclean

# Configure/build in optimized mode with tests
./waf -j1 --color=yes configure --with-tests
./waf -j1 --color=yes build

# Install
sudo ./waf install -j1 --color=yes
sudo ldconfig || true
