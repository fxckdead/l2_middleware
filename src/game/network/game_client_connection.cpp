#include "game_client_connection.hpp"
#include "game_connection_manager.hpp"

// =============================================================================
// Constructor
// =============================================================================

GameClientConnection::GameClientConnection(boost::asio::ip::tcp::socket socket,
                                            boost::asio::io_context &io_context,
                                            GameConnectionManager *manager)
    : BaseClientConnection(std::move(socket), io_context, manager)
{
    // Game client encryption will be initialized when we have a key
    // (after authentication with login server)
    
    log_connection_event("GameClientConnection created");
}

// =============================================================================
// State Management
// =============================================================================

void GameClientConnection::set_game_state(GameState new_state)
{
    GameState old_state = game_state_.load();
    
    if (!validate_game_state_transition(old_state, new_state))
    {
        log_connection_event("Invalid game state transition from " + 
                           std::string(game_state_to_string(old_state)) + 
                           " to " + std::string(game_state_to_string(new_state)));
        return;
    }
    
    game_state_.store(new_state);
    
    log_connection_event("Game state changed from " + 
                       std::string(game_state_to_string(old_state)) + 
                       " to " + std::string(game_state_to_string(new_state)));
}

// =============================================================================
// BaseClientConnection Implementation
// =============================================================================

void GameClientConnection::handle_complete_packet(std::vector<uint8_t> packet_data)
{
    try
    {
        if (packet_data.empty())
        {
            log_connection_event("Received empty packet");
            return;
        }

        // Decrypt the packet
        if (!decrypt_incoming_packet(packet_data))
        {
            log_connection_event("Failed to decrypt incoming packet");
            force_disconnect();
            return;
        }

        // TODO: Implement game packet factory and handling
        // For now, just log the packet
        uint8_t packet_type = packet_data[0];
        log_connection_event("Received game packet type: 0x" + 
                           std::to_string(packet_type) + 
                           " (" + std::to_string(packet_data.size()) + " bytes)");

        // TODO: Add game packet handlers here
        // auto packet_factory = GamePacketFactory();
        // auto packet = packet_factory.create_packet(packet_data);
        // handle_game_packet(packet);
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling packet: " + std::string(e.what()));
        force_disconnect();
    }
}

bool GameClientConnection::validate_state_transition(State from, State to) const
{
    // Basic state transition validation (can be extended)
    switch (from)
    {
    case State::CONNECTED:
        return to == State::DISCONNECTED; // Can only disconnect from connected
    case State::DISCONNECTED:
        return false; // Can't transition from disconnected
    default:
        return false;
    }
}

// =============================================================================
// Encryption Implementation
// =============================================================================

bool GameClientConnection::decrypt_incoming_packet(std::vector<uint8_t> &packet_data)
{
    try
    {
        if (game_encryption_)
        {
            return game_encryption_->decrypt(packet_data);
        }
        // If no encryption is set up yet, packets are in plaintext
        log_connection_event("Decrypting packet in plaintext mode (encryption not initialized)");
        return true;
    }
    catch (const std::exception &e)
    {
        log_connection_event("Decryption error: " + std::string(e.what()));
        return false;
    }
}

void GameClientConnection::encrypt_outgoing_packet(std::vector<uint8_t> &packet_data)
{
    try
    {
        if (game_encryption_)
        {
            game_encryption_->encrypt(packet_data);
        }
        // If no encryption is set up yet, packets are sent in plaintext
        else
        {
            log_connection_event("Encrypting packet in plaintext mode (encryption not initialized)");
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Encryption error: " + std::string(e.what()));
    }
}

// =============================================================================
// Game-Specific State Validation
// =============================================================================

bool GameClientConnection::validate_game_state_transition(GameState from, GameState to) const
{
    // Define valid game state transitions
    switch (from)
    {
    case GameState::CONNECTED:
        return to == GameState::AUTHENTICATED || to == GameState::DISCONNECTED;
    case GameState::AUTHENTICATED:
        return to == GameState::IN_GAME || to == GameState::DISCONNECTED;
    case GameState::IN_GAME:
        return to == GameState::DISCONNECTED;
    case GameState::DISCONNECTED:
        return false; // Can't transition from disconnected
    default:
        return false;
    }
}

// =============================================================================
// Encryption Management
// =============================================================================

void GameClientConnection::initialize_encryption(const std::vector<uint8_t> &key)
{
    try
    {
        game_encryption_ = std::make_unique<GameClientEncryption>(key);
        log_connection_event("Game client encryption initialized");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Failed to initialize encryption: " + std::string(e.what()));
    }
}

// =============================================================================
// Disconnect Handling
// =============================================================================

void GameClientConnection::on_disconnect()
{
    log_connection_event("Game client disconnected: " + player_name_);
    set_game_state(GameState::DISCONNECTED);
}

// =============================================================================
// Utility Functions
// =============================================================================

const char *game_state_to_string(GameClientConnection::GameState state)
{
    switch (state)
    {
    case GameClientConnection::GameState::CONNECTED:
        return "CONNECTED";
    case GameClientConnection::GameState::AUTHENTICATED:
        return "AUTHENTICATED";
    case GameClientConnection::GameState::IN_GAME:
        return "IN_GAME";
    case GameClientConnection::GameState::DISCONNECTED:
        return "DISCONNECTED";
    default:
        return "UNKNOWN";
    }
} 