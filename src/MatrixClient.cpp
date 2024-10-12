#include "MatrixClient.h"

MatrixClient::MatrixClient(std::string host_name, std::string port, boost::asio::io_context& io_context)
    : host(std::move(host_name)), port_(std::move(port)), ctx_(boost::asio::ssl::context::tlsv12_client),
        stream_(io_context, ctx_), resolver(io_context), write_timer_(stream_.get_executor()) {
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

void MatrixClient::stop() {
    try {
        // shutdown the ssl stream gracefully
        stream_.shutdown();
        // close the underlying socket
        boost::beast::get_lowest_layer(stream_).close();
    } catch (const std::exception& ec) {
        throw ec;
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
 * Overloaded method
 * this will use the token we grabbed during
 * the login
 * @return
 */
boost::asio::awaitable<void> MatrixClient::token_login() {
    namespace http = boost::beast::http;
    http::request<http::string_body> req {http::verb::post,  "/_matrix/client/r0/login", 11};

    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::content_type, "application/json");
    req.body() = generate_username_login_string(token);
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

void MatrixClient::parse_sync_response(const std::string &json_response) {
    boost::json::value sync_data = boost::json::parse(json_response);
    boost::json::object& sync_obj = sync_data.as_object();

    if (sync_obj.contains("rooms")) {
        auto& rooms = sync_obj["rooms"].as_object();
        auto& join_rooms = rooms["join"].as_object();

        for (auto& room : join_rooms) {
            auto& room_events = room.value().as_object()["timeline"].as_object()["events"].as_array();
            for (auto& event : room_events) {
                std::string event_type = event.as_object()["type"].as_string().c_str();
                if (event_type == "m.room.message") {
                    std::string sender = event.as_object()["sender"].as_string().c_str();
                    std::string message = event.as_object()["content"].as_object()["body"].as_string().c_str();
                    std::cout << "Message from " << sender << ": " << message << std::endl;
                }
                // Handle other event types...
            }
        }
    }

    next_sync_token = sync_obj["next_batch"].as_string().c_str();
    std::cout << "Next sync token: " << next_sync_token << std::endl;
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

void MatrixClient::start_sync() {
    try {
        // Start long polling coroutine
        boost::asio::co_spawn(stream_.get_executor(),
            [self = shared_from_this()] { return self->long_polling(); }, boost::asio::detached);
    } catch (std::exception&) {
        stop();
    }
}

boost::asio::awaitable<void> MatrixClient::long_polling() {
    namespace http = boost::beast::http;
    std::string sync_url = "/_matrix/client/r0/sync";


    try {
        while (boost::beast::get_lowest_layer(stream_).socket().is_open()) {
            http::request<http::string_body> req {http::verb::get, sync_url, 11};
            req.set(http::field::host, host);
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            req.set(http::field::authorization, "Bearer " + token);

            // Send the sync request
            co_await http::async_write(stream_, req, boost::asio::use_awaitable);

            boost::beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;

            // Read response from the server
            co_await http::async_read(stream_, buffer, res, boost::asio::use_awaitable);

            // Process the response
            if (res.result() == http::status::ok) {
                const std::string response_body = boost::beast::buffers_to_string(res.body().data());
                parse_sync_response(response_body);

                if (!next_sync_token.empty()) {
                    sync_url = std::format("/_matrix/client/r0/sync?since={}", next_sync_token);
                }

            } else {
                std::cerr << "HTTP request failed: " << res.result_int() << " " << res.reason() << std::endl;
                // Handle errors or retry logic here
            }
        }
    } catch (std::exception&) {
        stop();
    }
}


/**
 * starts long polling sets up reading and writing
 * this method assumes you are already connected
 * we start the writer method and the reader method
 * @return
 */
/**void MatrixClient::start_sync() {
    try {
        // TODO finish are long polling start sync method
        // start are infinite write operation
        boost::asio::co_spawn(stream_.get_executor(),
            [self = shared_from_this()] {return self->writer(); }, boost::asio::detached);

        // start our read operation
        boost::asio::co_spawn(stream_.get_executor(),
            [self = shared_from_this()] { return self->reader(); }, boost::asio::detached);

        // co_spawn loop that will push requests into the vectory which will then be
        // sent and read

    } catch (std::exception&) {
        stop();
    }
}**/

// saving these for when I implement SSE
/**
 * Sends a message to the server
 * @param request
 * @return
 **/
/**void MatrixClient::deliver(boost::beast::http::request<boost::beast::http::string_body>&& request) {
    // we'll be calling this most likely from multiple threads
    std::unique_lock<std::mutex> lock(write_mtx);
    write_msgs_.push_back(std::move(request));
    write_timer_.cancel_one();
}**/

/**
 * basically polls are
 * write message queue for messages
 * that are posted
 * @return
 **/
/**boost::asio::awaitable<void> MatrixClient::writer() {
    try {
        while (boost::beast::get_lowest_layer(stream_).socket().is_open()) {
            if (write_msgs_.empty()) {
                boost::system::error_code ec;
                co_await write_timer_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            } else {
                co_await boost::beast::http::async_write(stream_, write_msgs_.front(), boost::asio::use_awaitable);
            }
        }
    } catch (std::exception&) {
        stop();
    }
}**/

/**
 * reader method is going
 * to read need to setup a
 * a callback structure
 * so we can get our info
 * back to user
 * @return
 */
/**boost::asio::awaitable<void> MatrixClient::reader() {
    namespace http = boost::beast::http;
    try {
        while (boost::beast::get_lowest_layer(stream_).socket().is_open()) {
            boost::beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
            co_await http::async_read(stream_, buffer, res, boost::asio::use_awaitable);
        }
    } catch (std::exception&) {
        stop();
    }
}**/

std::string MatrixClient::generate_password_login_string(const std::string& username, const std::string& password) {
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
