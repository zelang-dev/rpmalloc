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

## catomic tests
add_executable(test-spmc thread.c test-spmc.c)
target_link_libraries(test-spmc rpmalloc)
add_test(NAME test-spmc COMMAND test-spmc)

add_executable(test-mpsc thread.c test-mpsc.c)
target_link_libraries(test-mpsc rpmalloc)
add_test(NAME test-mpsc COMMAND test-mpsc)

## stress test
add_executable(test-stress test-stress.c)
target_link_libraries(test-stress rpmalloc)
add_test(NAME test-stress COMMAND test-stress)

## leak test
add_executable(test-leak test-leak.c)
target_link_libraries(test-leak rpmalloc)
add_test(NAME test-leak COMMAND test-leak)
