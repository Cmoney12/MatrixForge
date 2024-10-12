cmake_minimum_required(VERSION 3.28)
project(MatrixForge)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

find_package(Boost 1.83.0 REQUIRED COMPONENTS system thread json)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    link_directories(${Boost_LIBRARY_DIRS})
endif(Boost_FOUND)

include_directories(include)
include_directories(src)

add_executable(${PROJECT_NAME} main.cpp
        include/MatrixClient.h
        src/MatrixClient.cpp
        include/Room.h
        include/Event.h
        include/User.h)

SET(USED_LIBS ${Boost_SYSTEM_LIBRARY} ${Boost_THREAD_LIBRARY} ${Boost_REGEX_LIBRARY} ${Boost_JSON_LIBRARY})

target_link_libraries(${PROJECT_NAME} ${USED_LIBS} OpenSSL::Crypto OpenSSL::SSL)

add_subdirectory(tests)