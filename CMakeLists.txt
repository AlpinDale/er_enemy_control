cmake_minimum_required(VERSION 3.20)
project(EldenRingEnemyControlCleanroom LANGUAGES CXX)

set(ERD_DIST_DIR "${CMAKE_BINARY_DIR}/dist")

add_library(erd_enemy_control SHARED
    src/dllmain.cpp
    src/pattern_scan.cpp
)

target_compile_features(erd_enemy_control PRIVATE cxx_std_20)
target_compile_definitions(erd_enemy_control PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

target_include_directories(erd_enemy_control PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

set_target_properties(erd_enemy_control PROPERTIES
    OUTPUT_NAME "elden_ring_enemy_control"
    RUNTIME_OUTPUT_DIRECTORY "${ERD_DIST_DIR}/EnemyControl"
    LIBRARY_OUTPUT_DIRECTORY "${ERD_DIST_DIR}/EnemyControl"
    ARCHIVE_OUTPUT_DIRECTORY "${ERD_DIST_DIR}/EnemyControl"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${ERD_DIST_DIR}/EnemyControl"
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${ERD_DIST_DIR}/EnemyControl"
    ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${ERD_DIST_DIR}/EnemyControl"
)

add_executable(erd_launcher
    src/launcher.cpp
)

target_compile_features(erd_launcher PRIVATE cxx_std_20)
target_compile_definitions(erd_launcher PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

set_target_properties(erd_launcher PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${ERD_DIST_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${ERD_DIST_DIR}"
)
