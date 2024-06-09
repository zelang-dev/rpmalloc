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
include(CheckCCompilerFlag)
include(CMakePackageConfigHelpers)

message("Generated with config types: ${CMAKE_CONFIGURATION_TYPES}")

set(CMAKE_CONFIGURATION_TYPES=Debug;Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")

cmake_dependent_option(BUILD_TESTING
  "Build the unit tests when BUILD_TESTING is enabled and we are the root project" OFF
  "BUILD_TESTING;CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR" OFF)

option(BUILD_SHARED_LIBS    "Build the library as a shared (dynamically-linked) " OFF)

if(UNIX)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -D ENABLE_ASSERTS=1")
else()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /D ENABLE_ASSERTS=1 ")
endif()

set(rpmalloc_files rpmalloc/rpmalloc.c )
if(BUILD_SHARED_LIBS)
    add_definitions(-DBUILD_DYNAMIC_LINK=1 -DENABLE_OVERRIDE=1)
    add_library(rpmalloc SHARED ${rpmalloc_files})
else()
    add_definitions(-DENABLE_OVERRIDE=1)
    add_library(rpmalloc STATIC ${rpmalloc_files})
endif()
set_property(TARGET rpmalloc PROPERTY POSITION_INDEPENDENT_CODE True)

find_package(Threads)
target_link_libraries(rpmalloc PUBLIC ${CMAKE_THREAD_LIBS_INIT})

if(BUILD_TESTING)
    enable_testing()
	add_subdirectory(test)
endif()