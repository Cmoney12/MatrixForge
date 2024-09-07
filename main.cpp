#include "MatrixClient.h"
#include <memory>

/**
 * just an example and for testing
 * purposes need a test account to test this
 * with
 * @param client
 * @return
 */
auto run(std::shared_ptr<MatrixClient> client) -> boost::asio::awaitable<void> {
    try {
        co_await client->connect();

        // Uncomment the desired login method
        // Login with username and password
        co_await client->password_login("username", "password");

        // Login with token
        //co_await client->token_login("your_login_token");
        //std::cout << "Logged in successfully" << std::endl;

        // Continue with other operations...

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
}

int main() {
    std::string host = "matrix.org";
    std::string port = "443";
    boost::asio::io_context io_context;

    auto client = std::make_shared<MatrixClient>(host, port, io_context);

    boost::asio::co_spawn(io_context, run(client), boost::asio::detached);

    io_context.run();

    return 0;

}

