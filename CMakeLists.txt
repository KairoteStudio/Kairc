cmake_minimum_required(VERSION 3.20)
project(Kairc VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

function(kairc_enable_warnings target)
    target_compile_options(${target} PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
    )
endfunction()

add_library(kairc_core
    src/channel.cpp
    src/config.cpp
    src/crypto.cpp
    src/event.cpp
    src/event_store.cpp
    src/irc.cpp
    src/node.cpp
    src/p2p.cpp
    src/socket.cpp
    src/types.cpp
)
target_include_directories(kairc_core PUBLIC include)
target_link_libraries(kairc_core
    PUBLIC
        PkgConfig::SODIUM
        SQLite3::SQLite3
        Threads::Threads
)
kairc_enable_warnings(kairc_core)

add_executable(kaircd src/main.cpp)
target_link_libraries(kaircd PRIVATE kairc_core)
kairc_enable_warnings(kaircd)

include(CTest)
option(KAIRC_ENABLE_INTEGRATION_TESTS "Run loopback two-node integration tests" OFF)
if(BUILD_TESTING)
    add_executable(kairc_tests tests/test_main.cpp)
    target_link_libraries(kairc_tests PRIVATE kairc_core)
    kairc_enable_warnings(kairc_tests)
    add_test(NAME kairc_tests COMMAND kairc_tests)

    if(KAIRC_ENABLE_INTEGRATION_TESTS)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        add_test(
            NAME kairc_e2e
            COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e.py
                    $<TARGET_FILE:kaircd>
        )
        set_tests_properties(kairc_e2e PROPERTIES TIMEOUT 30)
    endif()
endif()

install(TARGETS kaircd RUNTIME DESTINATION bin)
