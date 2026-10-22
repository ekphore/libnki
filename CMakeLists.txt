# SPDX-FileCopyrightText: 2026 Gauvain "GovanifY" Roussel-Tarbouriech <gauvain@govanify.com>
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.20)
project(libnki VERSION 0.1.0 LANGUAGES CXX)

# Canonical headers live beside their implementations. Export a namespaced SDK
# view in the build tree, keeping build-tree and installed includes identical.
set(LIBNKI_PUBLIC_HEADERS
    src/libnki.h
    src/model.h
    src/nki.h
)
foreach(header IN LISTS LIBNKI_PUBLIC_HEADERS)
    get_filename_component(name "${header}" NAME)
    configure_file("${header}" "${CMAKE_CURRENT_BINARY_DIR}/public/libnki/${name}" COPYONLY)
endforeach()

include(GNUInstallDirs)
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/libnki)
include(CMakePackageConfigHelpers)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(ZLIB REQUIRED)
find_package(SQLite3 REQUIRED)

set(LIBNKI_BUNDLED_KEY_PATH "" CACHE FILEPATH
    "Unsupported local private key to embed in libnki")

set(LIBNKI_BUNDLED_KEY_BYTES "")
set(LIBNKI_BUNDLED_KEY_SIZE 0)
if(LIBNKI_BUNDLED_KEY_PATH)
    if(NOT EXISTS "${LIBNKI_BUNDLED_KEY_PATH}")
        message(FATAL_ERROR
            "LIBNKI_BUNDLED_KEY_PATH does not exist: ${LIBNKI_BUNDLED_KEY_PATH}")
    endif()
    file(READ "${LIBNKI_BUNDLED_KEY_PATH}" LIBNKI_BUNDLED_KEY_HEX HEX)
    string(LENGTH "${LIBNKI_BUNDLED_KEY_HEX}" LIBNKI_BUNDLED_KEY_HEX_LENGTH)
    math(EXPR LIBNKI_BUNDLED_KEY_SIZE "${LIBNKI_BUNDLED_KEY_HEX_LENGTH} / 2")
    string(REGEX REPLACE "([0-9A-Fa-f][0-9A-Fa-f])"
        "std::byte{0x\\1}," LIBNKI_BUNDLED_KEY_BYTES
        "${LIBNKI_BUNDLED_KEY_HEX}")
    message(WARNING
        "libnki is embedding private key material for unsupported local use. "
        "This build and its binaries MUST NOT be distributed.")
endif()

configure_file(cmake/bundled_key.cpp.in bundled_key.cpp @ONLY)

add_library(libnki
    src/patch/document.cpp
    src/patch/repository.cpp
    src/patch/headers.cpp
    src/patch/parameters.cpp
    src/patch/instrument.cpp
    src/patch/bank.cpp
    src/patch/legacy/tags.cpp
    src/patch/legacy/k1.cpp
    src/patch/legacy/k2.cpp
    src/protection/authorization.cpp
    src/protection/keys.cpp
    src/container/monolith.cpp
    src/container/content.cpp
    src/container/cache.cpp
    src/sample/ncw.cpp
    src/sample/resource.cpp
    src/product/metadata.cpp
    src/product/validation.cpp
    src/product/resources.cpp
    src/ui/performance_view.cpp
    src/model.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/bundled_key.cpp
)
add_library(libnki::libnki ALIAS libnki)
target_compile_features(libnki PUBLIC cxx_std_20)
target_include_directories(libnki PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/public>
    $<INSTALL_INTERFACE:include>
)
if(MSVC)
    target_compile_options(libnki PRIVATE /W4 /permissive-)
else()
    target_compile_options(libnki PRIVATE -Wall -Wextra -Wpedantic)
endif()
target_link_libraries(libnki PRIVATE OpenSSL::Crypto ZLIB::ZLIB SQLite::SQLite3)

install(TARGETS libnki
    EXPORT libnkiTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${LIBNKI_PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libnki)
install(EXPORT libnkiTargets
    FILE libnkiTargets.cmake
    NAMESPACE libnki::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libnki)
configure_package_config_file(cmake/libnkiConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/libnkiConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libnki)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/libnkiConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libnkiConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/libnkiConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libnki)
