# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

cmake_minimum_required(VERSION 3.16)
project(rqft_package_consumer LANGUAGES C CXX)

find_package(rqft CONFIG REQUIRED)

add_executable(rqft_package_consumer main.c)
target_link_libraries(rqft_package_consumer PRIVATE rqft::rqft)
