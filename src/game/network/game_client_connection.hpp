#pragma once

#include "../../core/network/base_client_connection.hpp"
#include "../../core/encryption/game_client_encryption.hpp"

// Forward declarations
class GameConnectionManager;

class GameClientConnection : public BaseClientConnection
{
public:
    // Game-specific connection states
    enum class GameState
    {
        CONNECTED,      // Just connected
        AUTHENTICATED,  // Player authenticated from login server
        IN_GAME,        // Player in game world
        DISCONNECTED    // Connection closed
    };

    // Constructor
    GameClientConnection(boost::asio::ip::tcp::socket socket,
                         boost::asio::io_context &io_context,
                         GameConnectionManager *manager = nullptr);

    // Virtual destructor
    virtual ~GameClientConnection() = default;

public:
    // Game-specific state management
    void set_game_state(GameState new_state);
    GameState get_game_state() const { return game_state_.load(); }
    bool is_game_state(GameState expected_state) const { return get_game_state() == expected_state; }

    // Game-specific session management
    void set_player_name(const std::string &name) { player_name_ = name; }
    const std::string &get_player_name() const { return player_name_; }

    void set_character_id(uint32_t id) { character_id_ = id; }
    uint32_t get_character_id() const { return character_id_; }

    // Encryption management
    void initialize_encryption(const std::vector<uint8_t> &key);
    bool is_encryption_enabled() const { return game_encryption_ != nullptr; }

protected:
    // Implementation of virtual methods from BaseClientConnection
    void handle_complete_packet(std::vector<uint8_t> packet_data) override;
    bool validate_state_transition(State from, State to) const override;

    // Game-specific encryption handling
    bool decrypt_incoming_packet(std::vector<uint8_t> &packet_data) override;
    void encrypt_outgoing_packet(std::vector<uint8_t> &packet_data) override;

    // Game-specific state transition validation
    bool validate_game_state_transition(GameState from, GameState to) const;

private:
    // Game-specific state
    std::atomic<GameState> game_state_{GameState::CONNECTED};

    // Game-specific encryption state
    std::unique_ptr<GameClientEncryption> game_encryption_;

    // Game-specific session information
    std::string player_name_;
    uint32_t character_id_ = 0;

    // TODO: Game-specific packet handlers will be added here
    // void handle_player_auth_packet(...);
    // void handle_move_packet(...);
    // etc.

    // Game-specific disconnect handling
    void on_disconnect() override;
};

// Utility function for game state management
const char *game_state_to_string(GameClientConnection::GameState state); 