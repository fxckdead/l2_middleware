#pragma once

#include "../../core/network/base_connection_manager.hpp"
#include "game_client_connection.hpp"

class GameConnectionManager : public BaseConnectionManager
{
public:
    explicit GameConnectionManager(boost::asio::io_context &io_context, const Config &config);
    virtual ~GameConnectionManager() = default;

    // Override to create game-specific connections
    ConnectionPtr create_connection(boost::asio::ip::tcp::socket socket) override;

protected:
    // Override to initialize game-specific connection logic
    void initialize_connection(ConnectionPtr connection) override;

private:
    // Cast helper for type safety
    std::shared_ptr<GameClientConnection> cast_to_game_connection(ConnectionPtr connection);
}; 