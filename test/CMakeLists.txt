include_directories(${CMAKE_SOURCE_DIR}/rpmalloc ${CMAKE_SOURCE_DIR}/test)

add_executable(main_test thread.c main.c)
add_executable(storage_test thread.c storage.c)
add_executable(atomicity_test thread.c atomicity.c)

target_link_libraries(main_test rpmalloc)
target_link_libraries(storage_test rpmalloc)
target_link_libraries(atomicity_test rpmalloc)

add_test(NAME main_test COMMAND main_test)
add_test(NAME storage_test COMMAND storage_test)
add_test(NAME atomicity_test COMMAND atomicity_test)

## stress test
add_executable(test-stress test-stress.c)
target_link_libraries(test-stress rpmalloc)
add_test(NAME test-stress COMMAND test-stress)

## leak test
add_executable(test-leak test-leak.c)
target_link_libraries(test-leak rpmalloc)
add_test(NAME test-leak COMMAND test-leak)

## fragment test
add_executable(heap-fragmentor heap-fragmentor.c)
target_link_libraries(heap-fragmentor rpmalloc)
add_test(NAME heap-fragmentor COMMAND heap-fragmentor)
