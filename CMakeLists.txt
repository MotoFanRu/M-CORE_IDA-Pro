cmake_minimum_required(VERSION 3.28)
project(mcore_ida)

set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
# Uncomment it for IDA Pro 8.3 or use `cmake -DIDA_EA64=OFF` command line parameter.
# set(IDA_EA64 OFF CACHE BOOL "Whether addresses are 64-bit (sizeof(ea_t)==8)" FORCE)
find_package(IDA REQUIRED)

add_ida_module(mcore_ida PROCESSOR SOURCES ana.cpp emu.cpp ins.cpp ins.hpp mcore.hpp out.cpp reg.cpp)
target_link_libraries(mcore_ida PRIVATE IDA)
target_compile_definitions(mcore_ida PRIVATE _CRT_SECURE_NO_WARNINGS)
