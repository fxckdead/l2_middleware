#pragma once

#include "../../core/network/base_connection_manager.hpp"
#include "login_client_connection.hpp"
#include "../server/game_server_manager.hpp"

class LoginConnectionManager : public BaseConnectionManager
{
private:
    GameServerManager* game_server_manager_; // Non-owning pointer

public:
    explicit LoginConnectionManager(boost::asio::io_context &io_context,
                                    const Config &config,
                                    GameServerManager* game_server_manager);
    virtual ~LoginConnectionManager() = default;

    // Override to create login-specific connections
    ConnectionPtr create_connection(boost::asio::ip::tcp::socket socket) override;

    // Access to game server manager
    GameServerManager* get_game_server_manager() const { return game_server_manager_; }

protected:
    // Override to initialize login-specific connection logic
    void initialize_connection(ConnectionPtr connection) override;

private:
    // Cast helper for type safety
    std::shared_ptr<LoginClientConnection> cast_to_login_connection(ConnectionPtr connection);
};