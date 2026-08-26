# SPDX-FileCopyrightText: 2026 Tapio Measurement Technologies Oy
# SPDX-License-Identifier: GPL-3.0-only

# librqft CMake build, tests, install package, fuzz target, and interop peer.
cmake_minimum_required(VERSION 3.16)

set(RQFT_VERSION_OVERRIDE "" CACHE STRING
    "Override version derived from exact vMAJOR.MINOR.PATCH Git tag"
)
set(RQFT_VERSION_CANDIDATE "${RQFT_VERSION_OVERRIDE}")
if(NOT RQFT_VERSION_CANDIDATE AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/VERSION")
    file(READ "${CMAKE_CURRENT_LIST_DIR}/VERSION" RQFT_VERSION_CANDIDATE)
    string(STRIP "${RQFT_VERSION_CANDIDATE}" RQFT_VERSION_CANDIDATE)
endif()
if(NOT RQFT_VERSION_CANDIDATE)
    execute_process(
        COMMAND git describe --tags --exact-match --match "v[0-9]*"
        WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}"
        RESULT_VARIABLE RQFT_GIT_TAG_RESULT
        OUTPUT_VARIABLE RQFT_VERSION_CANDIDATE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT RQFT_GIT_TAG_RESULT EQUAL 0)
        set(RQFT_VERSION_CANDIDATE "0.0.0")
    endif()
endif()
if(NOT RQFT_VERSION_CANDIDATE MATCHES
   "^v?([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR
        "RQFT version must be vMAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH; "
        "got '${RQFT_VERSION_CANDIDATE}'"
    )
endif()
set(RQFT_VERSION_RESOLVED
    "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}"
)

project(rqft VERSION "${RQFT_VERSION_RESOLVED}" LANGUAGES C CXX)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(RQFT_TOP_LEVEL ON)
else()
    set(RQFT_TOP_LEVEL OFF)
endif()

set(RQFT_TESTS_DEFAULT OFF)
if(RQFT_TOP_LEVEL AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/header_smoke.c")
    set(RQFT_TESTS_DEFAULT ON)
endif()

set(RQFT_INTEROP_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../interop/c_peer/main.cpp")
set(RQFT_INTEROP_DEFAULT OFF)
if(RQFT_TOP_LEVEL AND EXISTS "${RQFT_INTEROP_SOURCE}")
    set(RQFT_INTEROP_DEFAULT ON)
endif()

option(RQFT_BUILD_TESTS "Build native unit and header tests" ${RQFT_TESTS_DEFAULT})
option(RQFT_BUILD_INTEROP "Build the native interoperability peer" ${RQFT_INTEROP_DEFAULT})
option(RQFT_BUILD_FUZZ "Build libFuzzer targets" OFF)
option(RQFT_SANITIZE "Instrument native targets with ASan/UBSan" OFF)
option(RQFT_WERROR "Treat librqft warnings as errors" ${RQFT_TOP_LEVEL})

add_library(rqft STATIC
    src/cobs.cpp
    src/crc32.cpp
    src/driver.cpp
    src/frame.cpp
    src/link.cpp
    src/message.cpp
    src/rto.cpp
    src/session.cpp
    src/version.cpp
)
add_library(rqft::rqft ALIAS rqft)
target_include_directories(rqft PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(rqft PRIVATE cxx_std_17)
target_compile_definitions(rqft PUBLIC
    RQFT_LIB_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    RQFT_LIB_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    RQFT_LIB_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    RQFT_LIB_VERSION_STRING="${PROJECT_VERSION}"
)

if(MSVC)
    target_compile_options(rqft PRIVATE /W4)
    if(RQFT_WERROR)
        target_compile_options(rqft PRIVATE /WX)
    endif()
else()
    target_compile_options(rqft PRIVATE -Wall -Wextra -Wconversion -Wshadow)
    if(RQFT_WERROR)
        target_compile_options(rqft PRIVATE -Werror)
    endif()
endif()

if(RQFT_SANITIZE)
    if(CMAKE_CROSSCOMPILING)
        message(FATAL_ERROR "RQFT_SANITIZE is unavailable while cross-compiling")
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "RQFT_SANITIZE requires GCC or Clang")
    endif()
    set(SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_options(rqft PUBLIC ${SAN_FLAGS})
    target_link_options(rqft PUBLIC ${SAN_FLAGS})
endif()

if(RQFT_BUILD_FUZZ)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz_frame.c")
        message(FATAL_ERROR "RQFT_BUILD_FUZZ requires c/tests/fuzz_frame.c")
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "RQFT_BUILD_FUZZ requires Clang/libFuzzer")
    endif()
    target_compile_options(rqft PRIVATE -fsanitize=fuzzer-no-link)
endif()

if(RQFT_BUILD_INTEROP)
    if(NOT EXISTS "${RQFT_INTEROP_SOURCE}")
        message(FATAL_ERROR "RQFT_BUILD_INTEROP requires interop/c_peer/main.cpp")
    endif()
    add_executable(c_peer "${RQFT_INTEROP_SOURCE}")
    target_link_libraries(c_peer PRIVATE rqft)
    target_compile_features(c_peer PRIVATE cxx_std_17)
    if(MSVC)
        target_compile_options(c_peer PRIVATE /W4)
        if(RQFT_WERROR)
            target_compile_options(c_peer PRIVATE /WX)
        endif()
    else()
        target_compile_options(c_peer PRIVATE -Wall -Wextra -Wconversion -Wshadow)
        if(RQFT_WERROR)
            target_compile_options(c_peer PRIVATE -Werror)
        endif()
    endif()
endif()

if(RQFT_BUILD_TESTS)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/header_smoke.c")
        message(FATAL_ERROR "RQFT_BUILD_TESTS requires the c/tests directory")
    endif()
    enable_testing()

    # Public headers must compile independently from both supported languages.
    set(RQFT_PUBLIC_HEADERS
        version.h
        common.h
        crc32.h
        cobs.h
        frame.h
        rto.h
        link.h
        message.h
        session.h
        driver.h
        rqft.h
    )
    foreach(header ${RQFT_PUBLIC_HEADERS})
        string(REPLACE "." "_" header_target ${header})
        foreach(language c cxx)
            add_library(header_${header_target}_${language} OBJECT
                tests/header_smoke.${language}
            )
            target_include_directories(header_${header_target}_${language} PRIVATE include)
            target_compile_definitions(header_${header_target}_${language} PRIVATE
                RQFT_HEADER="rqft/${header}"
            )
            if(MSVC)
                target_compile_options(header_${header_target}_${language} PRIVATE /W4)
                if(RQFT_WERROR)
                    target_compile_options(header_${header_target}_${language} PRIVATE /WX)
                endif()
            else()
                target_compile_options(header_${header_target}_${language} PRIVATE -Wall -Wextra)
                if(RQFT_WERROR)
                    target_compile_options(header_${header_target}_${language} PRIVATE -Werror)
                endif()
            endif()
        endforeach()
    endforeach()

    # Each c/tests/test_*.c is a standalone assert-based executable.
    file(GLOB RQFT_TEST_SOURCES CONFIGURE_DEPENDS tests/test_*.c)
    foreach(test_src ${RQFT_TEST_SOURCES})
        get_filename_component(test_name ${test_src} NAME_WE)
        add_executable(${test_name} ${test_src})
        target_link_libraries(${test_name} PRIVATE rqft)
        set_target_properties(${test_name} PROPERTIES LINKER_LANGUAGE CXX)
        if(MSVC)
            target_compile_options(${test_name} PRIVATE /W4)
        else()
            target_compile_options(${test_name} PRIVATE -Wall -Wextra)
        endif()
        target_compile_definitions(${test_name} PRIVATE
            RQFT_REPO_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/.."
        )
        if(test_name STREQUAL "test_no_heap" AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_link_options(${test_name} PRIVATE
                -Wl,--wrap=malloc
                -Wl,--wrap=calloc
                -Wl,--wrap=realloc
                -Wl,--wrap=free
            )
        endif()
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()

if(RQFT_BUILD_FUZZ)
    add_executable(fuzz_frame tests/fuzz_frame.c)
    target_link_libraries(fuzz_frame PRIVATE rqft)
    set_target_properties(fuzz_frame PROPERTIES LINKER_LANGUAGE CXX)
    target_compile_options(fuzz_frame PRIVATE
        -Wall
        -Wextra
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(fuzz_frame PRIVATE
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
endif()

set(RQFT_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/rqft")
configure_package_config_file(
    cmake/rqftConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/rqftConfig.cmake"
    INSTALL_DESTINATION "${RQFT_CMAKE_INSTALL_DIR}"
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/rqftConfigVersion.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
)

install(TARGETS rqft
    EXPORT rqftTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/rqft")
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/rqftConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/rqftConfigVersion.cmake"
    DESTINATION "${RQFT_CMAKE_INSTALL_DIR}"
)
install(EXPORT rqftTargets
    FILE rqftTargets.cmake
    NAMESPACE rqft::
    DESTINATION "${RQFT_CMAKE_INSTALL_DIR}"
)
