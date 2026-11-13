cmake_minimum_required(VERSION 3.22.1)
project(fracture_native C)

add_library(fracture_native SHARED native_probe.c)

target_link_libraries(fracture_native log)
