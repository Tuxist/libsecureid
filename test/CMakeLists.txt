add_executable(parse parse.c)
target_link_libraries(parse secureid)

add_test(NAME parse COMMAND parse "${CMAKE_SOURCE_DIR}/test/sid.txt")
set_tests_properties(parse PROPERTIES WILL_FAIL TRUE)
