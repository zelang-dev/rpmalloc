cmake_minimum_required(VERSION 2.8...3.14)

project(
    rpmalloc
    VERSION 2.1.6
    DESCRIPTION "General Purpose Memory Allocator"
    HOMEPAGE_URL "https://github.com/zelang-dev/rpmalloc"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 90)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

include(CMakeDependentOption)
include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(CMakePackageConfigHelpers)
include(CTest)

message("Generated with config types: ${CMAKE_CONFIGURATION_TYPES}")

if(WIN32)
    if($ENV{Platform} MATCHES x86)
        message("Building Windows x86-32bit")
        add_definitions(-D_WIN32_PLATFORM_X86=1)
    endif()
endif()

set(CMAKE_CONFIGURATION_TYPES=Debug;Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/build")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")

cmake_dependent_option(BUILD_TESTING
  "Build the unit tests when BUILD_TESTING is enabled and we are the root project" OFF
  "BUILD_TESTING;CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR" OFF)

option(BUILD_SHARED_LIBS    "Build the library as a shared (dynamically-linked) " OFF)

if(UNIX)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -D ENABLE_ASSERTS=1")
else()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /D ENABLE_ASSERTS=1 ")
    add_definitions("/wd4244")
endif()

set(rpmalloc_files rpmalloc/rpmalloc.c )
add_definitions(-DENABLE_OVERRIDE=1)
if(BUILD_SHARED_LIBS)
    add_library(rpmalloc SHARED ${rpmalloc_files})
else()
    add_library(rpmalloc STATIC ${rpmalloc_files})
endif()
set_property(TARGET rpmalloc PROPERTY POSITION_INDEPENDENT_CODE True)

find_package(Threads)
target_link_libraries(rpmalloc PUBLIC ${CMAKE_THREAD_LIBS_INIT})

if(BUILD_TESTING)
    enable_testing()
	add_subdirectory(test)
endif()
