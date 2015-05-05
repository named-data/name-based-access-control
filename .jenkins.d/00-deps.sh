#!/usr/bin/env bash
set -x
set -e

JDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "$JDIR"/util.sh

[[ -n $NODE_LABELS ]] || exit 0

if has OSX $NODE_LABELS; then
    brew update
    brew upgrade
    brew install boost pkg-config cryptopp
    brew cleanup
fi

if has Ubuntu $NODE_LABELS; then
    sudo apt-get update -qq -y
    sudo apt-get -qq -y install build-essential pkg-config
    sudo apt-get -qq -y install libcrypto++-dev

    if has Ubuntu-12.04 $NODE_LABELS; then
        sudo apt-get install -qq -y libboost1.48-all-dev
    else
        sudo apt-get install -qq -y libboost-all-dev
    fi
fi
