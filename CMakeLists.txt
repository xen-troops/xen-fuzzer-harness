# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

set(BOARD xenvm)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(xen-fuzzer-harness)

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/hypercall.c)
target_sources(app PRIVATE src/hyp.S)
