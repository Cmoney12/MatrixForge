#ifndef MATRIXCLIENT_H
#define MATRIXCLIENT_H

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/detached.hpp>
#include <boost/json.hpp>
#include <mutex>
#include <deque>
#include <string>
#include <memory>
#include <utility>
#include <iostream>

class MatrixClient : public std::enable_shared_from_this<MatrixClient> {
public:
    MatrixClient(std::string host_name, std::string port, boost::asio::io_context& io_context);

    boost::asio::awaitable<void> connect();

    void stop();

    boost::asio::awaitable<void> password_login(const std::string& username, const std::string& password);

    boost::asio::awaitable<void> token_login(const std::string& login_token);

    boost::asio::awaitable<void> token_login();

    void parse_sync_respone(const std::string& json_response);

    static std::string generate_password_login_string(const std::string& username, const std::string& password);

    static std::string generate_username_login_string(const std::string& token);

    static std::string parse_login_response(const std::string& response);

    void start_sync();

    boost::asio::awaitable<void> long_polling();

    //void deliver(boost::beast::http::request<boost::beast::http::string_body>&& request);

    //boost::asio::awaitable<void> writer();

    //boost::asio::awaitable<void> reader();

private:
    std::string host;
    std::string port_;
    boost::asio::ssl::context ctx_;
    boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
    boost::asio::ip::tcp::resolver resolver;
    std::deque<boost::beast::http::request<boost::beast::http::string_body>> write_msgs_;
    boost::asio::steady_timer write_timer_;
    std::string token;
    std::string next_sync_token;
    std::mutex write_mtx;
};

#endif //MATRIXCLIENT_H
