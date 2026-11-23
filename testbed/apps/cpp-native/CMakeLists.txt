cmake_minimum_required(VERSION 3.24)
project(cpp_native CXX)
include(FetchContent)
include(ExternalProject)

FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        master)

ExternalProject_Add(zlib_ext
  URL http://zlib.example.com/zlib-1.3.1.tar.gz)

FetchContent_MakeAvailable(json)
