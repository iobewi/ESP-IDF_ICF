cmake_minimum_required(VERSION 3.5)

set(COMPONENTS main)

set(EXTRA_COMPONENT_DIRS "${CMAKE_SOURCE_DIR}/../..")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(icf_tests)
