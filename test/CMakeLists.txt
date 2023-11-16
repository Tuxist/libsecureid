add_executable(parse parse.c)
target_link_libraries(parse secureid)

add_test(NAME parse COMMAND $<TARGET_FILE:parse> "${CMAKE_SOURCE_DIR}/test/sid.txt")

add_executable(copy copy.c)
target_link_libraries(copy secureid)

add_test(NAME copy COMMAND $<TARGET_FILE:copy> "${CMAKE_SOURCE_DIR}/test/sid.txt")

add_executable(rid rid.c)
target_link_libraries(rid secureid)

add_test(NAME rid COMMAND $<TARGET_FILE:rid> "${CMAKE_SOURCE_DIR}/test/sid.txt")
