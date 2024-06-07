cmake_minimum_required(VERSION 2.8...3.14)

add_executable(main_test thread.c main.c)
target_link_libraries(main_test rpmalloc)

add_test(NAME main_test COMMAND main_test)
