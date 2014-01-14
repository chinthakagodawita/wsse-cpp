# CMake file for compiling the static library.
# Copyright (c) 2014 Chinthaka Godawita <chin.godawita@me.com>
#
# Distributed under the BSD license (see LICENSE for more or copy at
# http://opensource.org/licenses/MIT).
#
# To use this, simply add this project as a Git submodule and use:
# add_subdirectory(wsse-cpp) in your make CMakeLists.txt file and link
# against the 'wsse-cpp' library.

cmake_minimum_required (VERSION 2.8.5 FATAL_ERROR)

project (wsse-cpp)

set (wsse-cpp_VERSION_MAJOR 0)
set (wsse-cpp_VERSION_MINOR 1)

# Use C++11 (MSVC does not require any special flags)
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  add_definitions (-std=c++11)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
  add_definitions (-std=c++0x)
endif()

# Make sure we include the include directory in the path
include_directories (${wsse-cpp_SOURCE_DIR}/include)

# Add sources as a 'wsse-cpp' library.
add_library (wsse-cpp STATIC
  include/wsse.hpp
  src/wsse.cpp
)
