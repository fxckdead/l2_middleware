#include "login_connection_manager.hpp"
#include <random>

// =============================================================================
// Constructor
// =============================================================================

LoginConnectionManager::LoginConnectionManager(boost::asio::io_context &io_context, const Config &config, GameServerManager* game_server_manager)
    : BaseConnectionManager(io_context, config), game_server_manager_(game_server_manager)
{
    log_connection_event("LoginConnectionManager initialized");
}

// =============================================================================
// Virtual Method Overrides
// =============================================================================

LoginConnectionManager::ConnectionPtr LoginConnectionManager::create_connection(boost::asio::ip::tcp::socket socket)
{
    if (is_connection_limit_reached())
    {
        log_connection_event("Connection limit reached, rejecting new connection");
        return nullptr;
    }

    // Create login-specific connection
    auto connection = std::make_shared<LoginClientConnection>(std::move(socket), io_context_, this);

    return std::static_pointer_cast<BaseClientConnection>(connection);
}

void LoginConnectionManager::initialize_connection(ConnectionPtr connection)
{
    try
    {
        // Get RSA key and generate Blowfish key
        const auto &rsa_pair = get_random_rsa_key();

        // Generate random Blowfish key
        std::vector<uint8_t> blowfish_key(16);
        std::random_device rd;
        std::mt19937 gen(rd());
        for (auto &byte : blowfish_key)
        {
            byte = static_cast<uint8_t>(gen() & 0xFF);
        }

        // Cast to login connection and send init packet
        if (auto login_connection = cast_to_login_connection(connection))
        {
            login_connection->send_init_packet(rsa_pair, blowfish_key);
        }
        else
        {
            log_connection_event("Failed to cast connection to LoginClientConnection");
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

std::shared_ptr<LoginClientConnection> LoginConnectionManager::cast_to_login_connection(ConnectionPtr connection)
{
    return std::dynamic_pointer_cast<LoginClientConnection>(connection);
}