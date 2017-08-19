cmake_minimum_required(VERSION 3.0)
project(libwebsite)

set(Sources
    src/core.c
    src/search.c
)

add_compile_options(
    -std=c99
)

add_library(${PROJECT_NAME} SHARED ${Sources})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")

target_link_libraries(${PROJECT_NAME} ev ssl)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)

add_subdirectory(test)