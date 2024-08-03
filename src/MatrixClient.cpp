#include "MatrixClient.h"

MatrixClient::MatrixClient(std::string host_name, std::string port, boost::asio::io_context& io_context)
    : host(std::move(host_name)), port_(std::move(port)), ctx_(boost::asio::ssl::context::tlsv12_client),
        stream_(io_context, ctx_), resolver(io_context) {
    ctx_.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx_.set_default_verify_paths();
}

/**
 * Establishes a connection to
 * our the matrix server
 * @return
 */
boost::asio::awaitable<void> MatrixClient::connect() {

    try {
        auto const results = co_await resolver.async_resolve(host, port_, boost::asio::use_awaitable);

        co_await boost::beast::get_lowest_layer(stream_).async_connect(results, boost::asio::use_awaitable);

        co_await stream_.async_handshake(boost::asio::ssl::stream_base::client, boost::asio::use_awaitable);
    }
    catch (const std::exception& ec) {
        // do something with this besides just printing it out
        std::cerr << ec.what() << std::endl;
    }
}

/**
 * Logins to the matrix server using
 * username and password also fetches our login token
 * @param username
 * @param password
 * @return
 */
boost::asio::awaitable<void> MatrixClient::password_login(const std::string &username, const std::string &password) {

    namespace http = boost::beast::http;
    http::request<http::string_body> req {http::verb::post,  "/_matrix/client/r0/login", 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::content_type, "application/json");
    req.body() = generate_password_login_string(username, password);
    req.prepare_payload();

    try {
        // send the http request for login
        co_await http::async_write(stream_, req, boost::asio::use_awaitable);

        // Declare a container to hold the response
        boost::beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;

        // receive the read response
        co_await http::async_read(stream_, buffer, res, boost::asio::use_awaitable);

        if (res.result() != http::status::ok) {
            std::cerr << "HTTP request failed: " << res.result_int() << " " << res.reason() << std::endl;
            // implement a stop method
        }

        const std::string response_body = boost::beast::buffers_to_string(res.body().data());

        token = parse_login_response(response_body);

    }
    catch (const std::exception& ec) {
       std::cerr << ec.what() << std::endl;
    }
}

/**
 *  Login to matrix server via
 *  token
 * @param login_token wanted to make it so
 * you could supply youre own token
 * @return
 */
boost::asio::awaitable<void> MatrixClient::token_login(const std::string& login_token) {

    namespace http = boost::beast::http;
    http::request<http::string_body> req {http::verb::post,  "/_matrix/client/r0/login", 11};

    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::content_type, "application/json");
    req.body() = generate_username_login_string(login_token);
    req.prepare_payload();

    try {
        co_await http::async_write(stream_, req, boost::asio::use_awaitable);

        boost::beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;

        co_await http::async_read(stream_, buffer, res, boost::asio::use_awaitable);

        if (res.result() != http::status::ok) {
            std::cerr << "HTTP request failed: " << res.result_int() << " " << res.reason() << std::endl;
        }

        const std::string response_body = boost::beast::buffers_to_string(res.body().data());
    }
    catch (const std::exception& ec) {
        std::cerr << ec.what() << std::endl;
    }
}

/**
 * parses the login response
 * @param response
 * @return
 */
std::string MatrixClient::parse_login_response(const std::string& response) {

    auto json_response = boost::json::parse(response);
    if (!json_response.is_object()) {
        throw std::runtime_error("Error: Invalid JSON response");
    }

    auto json_obj = json_response.as_object();
    if (!json_obj.contains("access_token")) {
        throw std::runtime_error("Error: No access token in response");
    }

    return json_obj["access_token"].as_string().c_str();
}

std::string MatrixClient::generate_password_login_string(const std::string &username, const std::string &password) {
    boost::json::object payload;
    payload["type"] = "m.login.password";
    payload["user"] = username;
    payload["password"] = password;

    return boost::json::serialize(payload);
}

std::string MatrixClient::generate_username_login_string(const std::string& token) {
    boost::json::object payload;
    payload["type"] = "m.login.token";
    payload["token"] = token;

    return boost::json::serialize(payload);
}
