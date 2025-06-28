#pragma once

#include "../../core/network/base_connection_manager.hpp"
#include "login_client_connection.hpp"

class LoginConnectionManager : public BaseConnectionManager
{
public:
    explicit LoginConnectionManager(boost::asio::io_context &io_context,
                                    const Config &config);
    virtual ~LoginConnectionManager() = default;

    // Override to create login-specific connections
    ConnectionPtr create_connection(boost::asio::ip::tcp::socket socket) override;

protected:
    // Override to initialize login-specific connection logic
    void initialize_connection(ConnectionPtr connection) override;

private:
    // Cast helper for type safety
    std::shared_ptr<LoginClientConnection> cast_to_login_connection(ConnectionPtr connection);
};