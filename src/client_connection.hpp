#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <functional>
#include <cstdint>
#include <string>
#include <atomic>

#include "login_encryption.hpp"
#include "game_client_encryption.hpp"
#include "session_key.hpp"
#include "rsa_manager.hpp"
#include "packet_factory.hpp"
#include "packet.hpp"

// Forward declarations
class ConnectionManager;

// Callback types for packet handling
using PacketHandler = std::function<void(std::shared_ptr<ReadablePacket>, class ClientConnection *)>;
using DisconnectHandler = std::function<void(class ClientConnection *)>;

class ClientConnection : public std::enable_shared_from_this<ClientConnection>
{
public:
    // Connection states matching the L2 authentication flow
    enum class State
    {
        CONNECTED,        // Just connected, no encryption
        INIT_SENT,        // Init packet sent, awaiting auth
        BLOWFISH_READY,   // Blowfish key sent, ready for login packets
        AUTHENTICATED,    // Successfully logged in
        GAME_ENCRYPTED,   // Using game client encryption
        SERVER_LIST_SENT, // Server list sent, awaiting selection
        PLAY_OK_SENT,     // Play OK sent, ready for game server
        DISCONNECTED      // Connection closed
    };

    // L2 packet framing constants (matching Rust implementation)
    static constexpr size_t PACKET_SIZE_BYTES = 2;
    static constexpr size_t MAX_PACKET_SIZE = 8192; // Reasonable max packet size
    static constexpr size_t READ_BUFFER_SIZE = 4096;

private:
    // Network components
    boost::asio::ip::tcp::socket socket_;
    boost::asio::io_context &io_context_;
    std::string remote_address_;

    // Packet framing (matching Rust read_packet logic)
    std::vector<uint8_t> read_buffer_;
    std::vector<uint8_t> partial_packet_buffer_; // For accumulating partial packets
    uint16_t expected_packet_size_ = 0;
    bool reading_header_ = true; // true when reading 2-byte length, false when reading packet body

    // Connection state
    std::atomic<State> connection_state_{State::CONNECTED};
    std::atomic<bool> is_connected_{true};

    // Encryption state
    std::unique_ptr<LoginEncryption> login_encryption_;
    std::unique_ptr<GameClientEncryption> game_encryption_;
    std::vector<uint8_t> blowfish_key_;

    // Session information
    SessionKey session_key_;
    std::string account_name_;
    int32_t session_id_;

    // RSA key pair for this connection
    const ScrambledRSAKeyPair *rsa_pair_ = nullptr;

    // Event handlers
    PacketHandler packet_handler_;
    DisconnectHandler disconnect_handler_;

    // Connection manager reference
    ConnectionManager *manager_ = nullptr;

public:
    // Constructor
    ClientConnection(boost::asio::ip::tcp::socket socket,
                     boost::asio::io_context &io_context,
                     ConnectionManager *manager = nullptr);

    // Destructor
    ~ClientConnection();

    // Connection lifecycle
    void start();
    void disconnect();
    void force_disconnect();

    // State queries
    bool is_connected() const { return is_connected_.load(); }
    State get_state() const { return connection_state_.load(); }
    const std::string &get_remote_address() const { return remote_address_; }

    // State management
    void set_state(State new_state);
    bool is_state(State expected_state) const { return get_state() == expected_state; }

    // Packet I/O (main interface)
    void send_packet(std::unique_ptr<SendablePacket> packet);
    void send_raw_packet(const std::vector<uint8_t> &packet_data);

    // High-level packet sending methods
    void send_init_packet(const ScrambledRSAKeyPair &rsa_pair,
                          const std::vector<uint8_t> &blowfish_key);
    void send_login_fail(uint8_t reason = 0x01);
    void send_server_list(); // TODO: Add server configuration
    void send_play_ok();

    // Encryption management
    void enable_login_encryption(const std::vector<uint8_t> &blowfish_key);
    void enable_game_encryption(const std::vector<uint8_t> &game_key);

    // Session management
    void set_session_key(const SessionKey &key) { session_key_ = key; }
    void set_account_name(const std::string &name) { account_name_ = name; }
    void set_session_id(int32_t id) { session_id_ = id; }

    const SessionKey &get_session_key() const { return session_key_; }
    const std::string &get_account_name() const { return account_name_; }
    int32_t get_session_id() const { return session_id_; }

    // RSA key management
    void set_rsa_key_pair(const ScrambledRSAKeyPair &rsa_pair) { rsa_pair_ = &rsa_pair; }
    const ScrambledRSAKeyPair *get_rsa_key_pair() const { return rsa_pair_; }

    // Event handler setup
    void set_packet_handler(PacketHandler handler) { packet_handler_ = std::move(handler); }
    void set_disconnect_handler(DisconnectHandler handler) { disconnect_handler_ = std::move(handler); }

    // New method to send raw init packet
    void send_init_packet_raw(const std::vector<uint8_t> &packet_data);

private:
    // Async I/O methods (matching Rust connection.rs pattern)
    void do_read();
    void handle_read(const boost::system::error_code &error, size_t bytes_transferred);
    void process_read_data(size_t bytes_available);
    void handle_complete_packet(std::vector<uint8_t> packet_data);

    void do_write(std::shared_ptr<std::vector<uint8_t>> data);
    void handle_write(const boost::system::error_code &error, size_t bytes_transferred,
                      std::shared_ptr<std::vector<uint8_t>> data);

    // Packet processing
    bool decrypt_incoming_packet(std::vector<uint8_t> &packet_data);
    void encrypt_outgoing_packet(std::vector<uint8_t> &packet_data);
    std::vector<uint8_t> prepare_packet_for_transmission(const std::vector<uint8_t> &packet_data);

    // L2 packet framing helpers
    void add_blowfish_padding(std::vector<uint8_t> &packet_data);

    // Packet framing (matching Rust read_packet logic)
    bool try_read_packet_header(const uint8_t *data, size_t available_bytes, size_t &consumed);
    bool try_read_packet_body(const uint8_t *data, size_t available_bytes, size_t &consumed,
                              std::vector<uint8_t> &complete_packet);

    // Utility methods
    void log_connection_event(const std::string &event) const;
    void handle_connection_error(const boost::system::error_code &error);
    void cleanup_connection();

    // State validation
    bool validate_state_transition(State from, State to) const;
};

// Utility functions for state management
const char *state_to_string(ClientConnection::State state);
bool is_valid_state_transition(ClientConnection::State from, ClientConnection::State to);