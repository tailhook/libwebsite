cmake_minimum_required(VERSION 3.0)

set(test_sources
    detailed.c
    routing.c
    simple.c
    websocket.c
    runtests.c
)

foreach(test_src ${test_sources})
    string(REPLACE ".c" "" ex_name ${test_src})
    add_executable(${ex_name} ${test_src})
    target_link_libraries(${ex_name} ${PROJECT_NAME})
endforeach()

# Runtests depends on cunit
target_link_libraries(runtests cunit)

# Install test runner script
configure_file(httptest.py ${CMAKE_CURRENT_BINARY_DIR}/conffiles/httptest.py COPYONLY)
file(COPY ${CMAKE_CURRENT_BINARY_DIR}/conffiles/httptest.py 
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
    FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
)
