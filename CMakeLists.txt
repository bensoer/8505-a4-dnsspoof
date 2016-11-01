cmake_minimum_required(VERSION 3.6)
project(8505_a4_dnsspoof)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lpcap")
# set the bin folder location
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(SOURCE_FILES src/dnsspoof/main.cpp src/dnsspoof/Structures.h src/dnsspoof/Logger.h src/dnsspoof/Logger.cpp src/dnsspoof/NetworkMonitor.h src/dnsspoof/NetworkMonitor.cpp)
add_executable(8505_a4_dnsspoof ${SOURCE_FILES})