# Longfellow ZK


[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE) [![eprint](https://img.shields.io/badge/eprint-2024%2F2010-blue)](https://eprint.iacr.org/2024/2010)
[![IETF Draft](https://img.shields.io/badge/IETF%20Draft-draft--google--cfrg--libzk-lightgrey)](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)
## Overview

The Longfellow library enables the construction of  zero-knowledge protocols concerning legacy identity verification standards such as the ISO MDOC standard, the JWT standard, and W3 Verifiable Credentials.  This implementation is described in:

* [Anonymous credentials from ECDSA](https://eprint.iacr.org/2024/2010)
* [libzk: A C++ Library for Zero-Knowledge Proofs](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)

It is named after the bridge outside the Google Cambridge office.

# Instructions to build

## Requirements

This package depends on cmake, openssl, zstd, clang, googletest and
googlebenchmark.

`$ sudo apt install libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev`

## Building manually

First run the cmake initialization step

`$ CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B clang-build-release --install-prefix ${PWD}/install`

Next:

`$ cd clang-build-release && make -j 16 && ctest -j 16`

