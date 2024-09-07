#include "MatrixClient.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

// Test the generate_password_login_string method
TEST(MatrixClientTest, GeneratePasswordLoginString) {
    std::string username = "testuser";
    std::string password = "password123";
    std::string expected = R"({"type":"m.login.password","user":"testuser","password":"password123"})";

    std::string result = MatrixClient::generate_password_login_string(username, password);
    EXPECT_EQ(result, expected);
}

// Test the generate_username_login_string method
TEST(MatrixClientTest, GenerateUsernameLoginString) {
    const std::string token = "dummy_token";
    const std::string expected = R"({"type":"m.login.token","token":"dummy_token"})";

    std::string result = MatrixClient::generate_username_login_string(token);
    EXPECT_EQ(result, expected);
}


