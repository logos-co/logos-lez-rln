cmake_minimum_required(VERSION 3.20)
project(logos_rln_module LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Options ----
set(LOGOS_CORE_ROOT "" CACHE PATH "Path to logos-core root directory.")
set(LEZ_RLN_FFI_ROOT "" CACHE PATH "Path to lez-rln-ffi source root (build from source).")
set(LEZ_RLN_FFI_LIB "" CACHE PATH "Path to prebuilt lez-rln-ffi lib directory.")
set(LEZ_RLN_FFI_INCLUDE "" CACHE PATH "Path to prebuilt lez-rln-ffi include directory.")

set(HAS_LOGOS_CORE_ROOT FALSE)
set(HAS_LEZ_RLN_FFI_ROOT FALSE)
set(HAS_LEZ_RLN_FFI_LIB FALSE)
set(HAS_LEZ_RLN_FFI_INCLUDE FALSE)

if (DEFINED LOGOS_CORE_ROOT AND NOT "${LOGOS_CORE_ROOT}" STREQUAL "")
    set(HAS_LOGOS_CORE_ROOT TRUE)
endif()

if (DEFINED LEZ_RLN_FFI_ROOT AND NOT "${LEZ_RLN_FFI_ROOT}" STREQUAL "")
    set(HAS_LEZ_RLN_FFI_ROOT TRUE)
endif()

if(DEFINED LEZ_RLN_FFI_LIB AND NOT "${LEZ_RLN_FFI_LIB}" STREQUAL "")
    set(HAS_LEZ_RLN_FFI_LIB TRUE)
endif()

if(DEFINED LEZ_RLN_FFI_INCLUDE AND NOT "${LEZ_RLN_FFI_INCLUDE}" STREQUAL "")
    set(HAS_LEZ_RLN_FFI_INCLUDE TRUE)
endif()

if (NOT HAS_LOGOS_CORE_ROOT)
    message(FATAL_ERROR "LOGOS_CORE_ROOT must be set to the logos-core root directory.")
endif()

if(HAS_LEZ_RLN_FFI_LIB AND HAS_LEZ_RLN_FFI_INCLUDE AND NOT HAS_LEZ_RLN_FFI_ROOT)
    message(STATUS "Using prebuilt lez-rln-ffi.")
    set(LEZ_RLN_FFI_PREBUILT TRUE)
elseif(NOT HAS_LEZ_RLN_FFI_LIB AND NOT HAS_LEZ_RLN_FFI_INCLUDE AND HAS_LEZ_RLN_FFI_ROOT)
    message(STATUS "Building lez-rln-ffi from source.")
    set(LEZ_RLN_FFI_PREBUILT FALSE)
else()
    message(FATAL_ERROR "Either both LEZ_RLN_FFI_LIB and LEZ_RLN_FFI_INCLUDE must be set for prebuilt lez-rln-ffi, or LEZ_RLN_FFI_ROOT must be set to build from source.")
endif()

# ---- Qt ----
find_package(Qt6 REQUIRED COMPONENTS Core RemoteObjects)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# ---- Directories ----
set(WORKSPACE_ROOT  "${CMAKE_BINARY_DIR}/workspace")
file(MAKE_DIRECTORY "${WORKSPACE_ROOT}")

# ---- Logos Core SDK ----
set(SDK_LIB "${LOGOS_CORE_ROOT}/lib/liblogos_sdk.a")
set(SDK_INC "${LOGOS_CORE_ROOT}/include")

# ---- OS Specifics ----
if(APPLE)
    set(DYLIB_EXT ".dylib")
elseif(WIN32)
    set(DYLIB_EXT ".dll")
    set(IMPLIB_EXT ".lib")
else()
    set(DYLIB_EXT ".so")
endif()

# ---- lez-rln-ffi (build OR consume) ----
if(LEZ_RLN_FFI_PREBUILT)
    set(LEZ_RLN_FFI_DYLIB "${LEZ_RLN_FFI_LIB}/liblez_rln_ffi${DYLIB_EXT}")

    if(WIN32)
        set(LEZ_RLN_FFI_IMPLIB "${LEZ_RLN_FFI_LIB}/lez_rln_ffi${IMPLIB_EXT}")
    endif()

    add_custom_target(lez_rln_ffi_libs)

else()
    find_program(CARGO_EXECUTABLE cargo REQUIRED)

    set(CARGO_TARGET_DIR       "${WORKSPACE_ROOT}/lez-rln-ffi/target")
    set(INTERNAL_STAGE         "${WORKSPACE_ROOT}/stage")
    set(INTERNAL_STAGE_LIB     "${INTERNAL_STAGE}/lib")
    set(INTERNAL_STAGE_INCLUDE "${INTERNAL_STAGE}/include")
    file(MAKE_DIRECTORY "${CARGO_TARGET_DIR}" "${INTERNAL_STAGE_LIB}" "${INTERNAL_STAGE_INCLUDE}")

    set(LEZ_RLN_FFI_LIB     "${INTERNAL_STAGE_LIB}")
    set(LEZ_RLN_FFI_INCLUDE "${INTERNAL_STAGE_INCLUDE}")

    set(LEZ_RLN_FFI_DYLIB  "${INTERNAL_STAGE_LIB}/liblez_rln_ffi${DYLIB_EXT}")
    set(LEZ_RLN_FFI_HEADER "${INTERNAL_STAGE_INCLUDE}/lez_rln_ffi.h")

    add_custom_command(
            OUTPUT "${LEZ_RLN_FFI_DYLIB}"
            COMMAND ${CMAKE_COMMAND} -E env
            CARGO_TARGET_DIR=${CARGO_TARGET_DIR}
            ${CARGO_EXECUTABLE} build --release
            --package lez-rln-ffi
            --manifest-path "${LEZ_RLN_FFI_ROOT}/Cargo.toml"
            COMMAND ${CMAKE_COMMAND} -E copy
            "${CARGO_TARGET_DIR}/release/liblez_rln_ffi${DYLIB_EXT}"
            "${LEZ_RLN_FFI_DYLIB}"
            DEPENDS "${LEZ_RLN_FFI_ROOT}/Cargo.toml"
            VERBATIM
    )

    add_custom_command(
            OUTPUT "${LEZ_RLN_FFI_HEADER}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${LEZ_RLN_FFI_ROOT}/lez-rln-ffi/lez_rln_ffi.h"
            "${LEZ_RLN_FFI_HEADER}"
            DEPENDS "${LEZ_RLN_FFI_DYLIB}"
            VERBATIM
    )

    add_custom_target(lez_rln_ffi_libs DEPENDS "${LEZ_RLN_FFI_DYLIB}" "${LEZ_RLN_FFI_HEADER}")
endif()

# ---- Imported targets ----
add_library(lez_rln_ffi SHARED IMPORTED GLOBAL)
set_target_properties(lez_rln_ffi PROPERTIES
        IMPORTED_LOCATION "${LEZ_RLN_FFI_DYLIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${LEZ_RLN_FFI_INCLUDE}"
)

if(NOT LEZ_RLN_FFI_PREBUILT)
    add_dependencies(lez_rln_ffi lez_rln_ffi_libs)
endif()

if(WIN32)
    set_target_properties(lez_rln_ffi PROPERTIES IMPORTED_IMPLIB "${LEZ_RLN_FFI_IMPLIB}")
endif()

add_library(logos_core STATIC IMPORTED
        src/i_logos_rln_module.h)
set_target_properties(logos_core PROPERTIES
        IMPORTED_LOCATION "${SDK_LIB}"
)

add_library(logos_cpp_sdk INTERFACE)
target_include_directories(logos_cpp_sdk INTERFACE "${SDK_INC}")

# ---- Plugin ----
set(PLUGIN_TARGET logos_rln_module)

qt_add_plugin(${PLUGIN_TARGET} CLASS_NAME LogosRlnModule)

target_sources(${PLUGIN_TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/logos_rln_module.cpp
)

set_property(TARGET ${PLUGIN_TARGET} PROPERTY PUBLIC_HEADER
        ${CMAKE_CURRENT_SOURCE_DIR}/src/i_logos_rln_module.h
)

target_include_directories(${PLUGIN_TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PLUGIN_TARGET} PRIVATE
        Qt6::Core
        Qt6::RemoteObjects
        lez_rln_ffi
        logos_cpp_sdk
        logos_core
)

target_compile_definitions(${PLUGIN_TARGET} PRIVATE
        LOGOS_RLN_MODULE_METADATA_FILE="${CMAKE_CURRENT_SOURCE_DIR}/metadata.json"
)

add_dependencies(${PLUGIN_TARGET} lez_rln_ffi_libs)

if(APPLE)
    set_target_properties(${PLUGIN_TARGET} PROPERTIES
            BUILD_RPATH "@loader_path"
            INSTALL_RPATH "@loader_path"
    )
elseif(UNIX)
    set_target_properties(${PLUGIN_TARGET} PROPERTIES
            BUILD_RPATH "$ORIGIN"
            INSTALL_RPATH "$ORIGIN"
    )
endif()

# ---- Install ----
install(TARGETS ${PLUGIN_TARGET}
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        PUBLIC_HEADER DESTINATION include
)
install(DIRECTORY "${LEZ_RLN_FFI_INCLUDE}/" DESTINATION include)
install(FILES "${LEZ_RLN_FFI_DYLIB}" DESTINATION lib)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/liblogos_rln_module_api.h" DESTINATION include)
