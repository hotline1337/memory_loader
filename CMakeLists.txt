cmake_minimum_required(VERSION 3.15)
project(Impulse_Loader)

set(CMAKE_CXX_STANDARD 20)

include_directories(.)

add_executable(Impulse_Loader
        bytes_of_files.h
        color.hpp
        CreateRemoteThread.cpp
        Main.cpp
        memory_injection.cpp
        memory_injection.h
        NtCreateThreadEx.cpp
        xorstr.h)
