#include "game_connection_manager.hpp"

// =============================================================================
// Constructor
// =============================================================================

GameConnectionManager::GameConnectionManager(boost::asio::io_context &io_context, const Config &config)
    : BaseConnectionManager(io_context, config)
{
    log_connection_event("GameConnectionManager initialized");
}

// =============================================================================
// Virtual Method Overrides
// =============================================================================

GameConnectionManager::ConnectionPtr GameConnectionManager::create_connection(boost::asio::ip::tcp::socket socket)
{
    if (is_connection_limit_reached())
    {
        log_connection_event("Connection limit reached, rejecting new connection");
        return nullptr;
    }

    // Create game-specific connection
    auto connection = std::make_shared<GameClientConnection>(std::move(socket), io_context_, this);

    return std::static_pointer_cast<BaseClientConnection>(connection);
}

void GameConnectionManager::initialize_connection(ConnectionPtr connection)
{
    try
    {
        // Cast to game connection for game-specific initialization
        if (auto game_connection = cast_to_game_connection(connection))
        {
            // TODO: Game servers might send different initialization packets
            // For now, just log that connection is ready
            log_connection_event("Game connection initialized and ready");
        }
        else
        {
            log_connection_event("Failed to cast connection to GameClientConnection");
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error initializing connection: " + std::string(e.what()));
        connection->force_disconnect();
    }
}

// =============================================================================
// Private Methods
// =============================================================================

std::shared_ptr<GameClientConnection> GameConnectionManager::cast_to_game_connection(ConnectionPtr connection)
{
    return std::dynamic_pointer_cast<GameClientConnection>(connection);
} 