cmake_minimum_required(VERSION 3.20)
project(mix_simulation_module LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
set(LOGOS_CORE_ROOT "" CACHE PATH "Path to logos-core/logos-cpp-sdk root directory.")

if (NOT DEFINED LOGOS_CORE_ROOT OR "${LOGOS_CORE_ROOT}" STREQUAL "")
    message(FATAL_ERROR "LOGOS_CORE_ROOT must be set to the logos-cpp-sdk root directory.")
endif()

# Qt
find_package(Qt6 REQUIRED COMPONENTS Core RemoteObjects)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Logos Core SDK
set(SDK_LIB "${LOGOS_CORE_ROOT}/lib/liblogos_sdk.a")
set(SDK_INC "${LOGOS_CORE_ROOT}/include")

# Verify SDK exists
if(NOT EXISTS "${SDK_LIB}")
    message(FATAL_ERROR "liblogos_sdk.a not found at ${SDK_LIB}")
endif()

# Imported targets
add_library(logos_core STATIC IMPORTED)
set_target_properties(logos_core PROPERTIES
    IMPORTED_LOCATION "${SDK_LIB}"
)

add_library(logos_cpp_sdk INTERFACE)
target_include_directories(logos_cpp_sdk INTERFACE "${SDK_INC}")

# Plugin
set(PLUGIN_TARGET mix_simulation_module)

qt_add_plugin(${PLUGIN_TARGET} CLASS_NAME MixSimulationModule)

target_sources(${PLUGIN_TARGET} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mix_simulation_module.cpp
)

set_property(TARGET ${PLUGIN_TARGET} PROPERTY PUBLIC_HEADER
    ${CMAKE_CURRENT_SOURCE_DIR}/src/i_mix_simulation_module.h
)

target_include_directories(${PLUGIN_TARGET} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${PLUGIN_TARGET} PRIVATE
    Qt6::Core
    Qt6::RemoteObjects
    logos_cpp_sdk
    logos_core
)

target_compile_definitions(${PLUGIN_TARGET} PRIVATE
    MIX_SIMULATION_MODULE_METADATA_FILE="${CMAKE_CURRENT_SOURCE_DIR}/metadata.json"
)

# RPATH settings
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

# Install
install(TARGETS ${PLUGIN_TARGET}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include
)
