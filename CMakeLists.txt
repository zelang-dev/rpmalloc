cmake_minimum_required(VERSION 2.8...3.14)

project(
    rpmalloc
    VERSION 1.4.5
    DESCRIPTION "General Purpose Memory Allocator"
    HOMEPAGE_URL "https://github.com/mjansson/rpmalloc"
    LANGUAGES C
)

set(C_STANDARD 89)

include(CMakeDependentOption)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

message("Generated with config types: ${CMAKE_CONFIGURATION_TYPES}")

set(CMAKE_CONFIGURATION_TYPES=Debug;Release)
set(BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")

cmake_dependent_option(BUILD_TESTING
  "Build the unit tests when BUILD_TESTING is enabled and we are the root project" OFF
  "BUILD_TESTING;CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR" OFF)

option(BUILD_SHARED_LIBS    "Build the library as a shared (dynamically-linked) " OFF)

set(rpmalloc_files ${CMAKE_CURRENT_SOURCE_DIR}/rpmalloc/rpmalloc.c )

add_definitions(-DENABLE_OVERRIDE=1)
if(BUILD_SHARED_LIBS)
    add_library(rpmalloc SHARED ${rpmalloc_files})
else()
    add_library(rpmalloc STATIC ${rpmalloc_files})
endif()

find_package(Threads)
target_link_libraries(rpmalloc PUBLIC ${CMAKE_THREAD_LIBS_INIT})

enable_testing()
if(BUILD_TESTING)
	add_subdirectory(test)
endif()
