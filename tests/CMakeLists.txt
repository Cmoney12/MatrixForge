# Find Google Test
include(FetchContent)

FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        release-1.12.1 # Use the latest stable release
)

FetchContent_MakeAvailable(googletest)

# Enable testing
enable_testing()

# Add test executable
add_executable(MatrixClientTests MatrixClientTest.cpp ../src/MatrixClient.cpp
)

# Link the test executable with Google Test, Boost, and OpenSSL
target_link_libraries(MatrixClientTests
        gtest
        gtest_main
        gmock
        gmock_main
        ${Boost_SYSTEM_LIBRARY}
        ${Boost_THREAD_LIBRARY}
        ${Boost_REGEX_LIBRARY}
        ${Boost_JSON_LIBRARY}
        OpenSSL::Crypto
        OpenSSL::SSL
)

# Discover and register tests
include(GoogleTest)
gtest_discover_tests(MatrixClientTests)
