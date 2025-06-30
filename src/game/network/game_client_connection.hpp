#pragma once

#include "../../core/network/base_client_connection.hpp"
#include "../../core/encryption/game_client_encryption.hpp"
#include "../../core/encryption/login_encryption.hpp"
#include "../packets/requests/no_op_packet.hpp"

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
    bool is_encryption_enabled() const { return blowfish_encryption_ != nullptr || game_encryption_ != nullptr; }
    
    // Override send_packet to use 8-byte padding for Blowfish (Game Server specific)
    void send_packet(std::unique_ptr<SendablePacket> packet) override;

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
    std::unique_ptr<GameClientEncryption> game_encryption_;  // XOR-based encryption used by client
    std::unique_ptr<LoginEncryption> blowfish_encryption_;   // (Optional) Blowfish for alternative clients

    // Game-specific session information
    std::string player_name_;
    uint32_t character_id_ = 0;

    // Game-specific packet handlers
    void handle_game_packet(std::unique_ptr<ReadablePacket> packet, uint8_t actual_opcode, const std::vector<uint8_t>& raw_packet_data);
    
    // TODO: Specific packet handlers will be added here
    // void handle_player_auth_packet(...);
    // void handle_move_packet(...);
    // etc.

    void handle_no_op_packet(const std::unique_ptr<ReadablePacket>& packet);
    void handle_protocol_version_packet(const std::unique_ptr<ReadablePacket>& packet);
    void handle_request_login_packet(const std::unique_ptr<ReadablePacket>& packet);
    void handle_request_new_character_packet(const std::unique_ptr<ReadablePacket>& packet);
    void handle_character_create_raw_data(const std::vector<uint8_t>& packet_data);
    void handle_character_create_packet(const std::unique_ptr<ReadablePacket>& packet);

    // Game-specific disconnect handling
    void on_disconnect() override;
};

// Utility function for game state management
const char *game_state_to_string(GameClientConnection::GameState state); 