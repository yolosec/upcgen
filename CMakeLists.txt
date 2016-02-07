cmake_minimum_required(VERSION 2.8)
project(upcgen)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        main.cpp
        main.h
        ahocorasick/actypes.h
        ahocorasick/ahocorasick.h
        ahocorasick/ahocorasick.c
        ahocorasick/mpool.h
        ahocorasick/mpool.c
        ahocorasick/node.h
        ahocorasick/node.c
        ahocorasick/replace.h
        ahocorasick/replace.c)

set(SOURCE_FILES_UPC
        upc_keys_gen.h
        upc_keys_gen.cpp
        ahocorasick/actypes.h
        ahocorasick/ahocorasick.h
        ahocorasick/ahocorasick.c
        ahocorasick/mpool.h
        ahocorasick/mpool.c
        ahocorasick/node.h
        ahocorasick/node.c
        ahocorasick/replace.h
        ahocorasick/replace.c)

add_executable(upcgen ${SOURCE_FILES})
add_executable(upckeysgen ${SOURCE_FILES_UPC})

# OpenSSL
find_library(OPENSSL_LIB crypto $ENV{OPENSSL_LIB_PATH})
if(NOT OPENSSL_LIB)
    message(FATAL_ERROR "OpenSSL library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif()
message("OPENSSL_LIB: ${OPENSSL_LIB}, include dir: ${OPENSSL_INCLUDE_DIR}, version: ${OPENSSL_VERSION}, root: ${OPENSSL_ROOT_DIR}, path: $ENV{OPENSSL_LIB_PATH}")
LINK_DIRECTORIES(${LINK_DIRECTORIES} ${OPENSSL_LIB})

find_path(OPENSSL_INCLUDE_PATH openssl/md5.h $ENV{OPENSSL_LIB_PATH} PATHS /opt/local /usr/local /usr)
if(NOT OPENSSL_INCLUDE_PATH)
    message(FATAL_ERROR "OpenSSL library include files not found.")
endif()
message("OPENSSL_INCLUDE_PATH: ${OPENSSL_INCLUDE_PATH}")
include_directories(${INCLUDE_DIRECTORIES} ${OPENSSL_INCLUDE_PATH})

# SQLite
find_library(SQLITE3_LIB sqlite3 $ENV{SQLITE3_LIB_PATH} PATHS /opt/local /usr/local /usr)
if(NOT SQLITE3_LIB)
    message(FATAL_ERROR "SQLite3 library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif()
message("SQLITE3_LIB: ${SQLITE3_LIB}")
LINK_DIRECTORIES(${LINK_DIRECTORIES} ${SQLITE3_LIB})

# Linking
target_link_libraries(upcgen ${OPENSSL_LIB} ${SQLITE3_LIB})
target_link_libraries(upckeysgen ${OPENSSL_LIB} ${SQLITE3_LIB})

# Release mode for fast computation
set(CMAKE_BUILD_TYPE Release)
