#pragma once

#include "../../core/network/base_client_connection.hpp"
#include "../../core/encryption/login_encryption.hpp"
#include "../../core/utils/session_key.hpp"
#include "../../core/encryption/rsa_manager.hpp"
#include "../packets/packet_factory.hpp"
#include "../packets/requests/auth_login_packet.hpp"
#include "../packets/requests/request_auth_gg.hpp"

// Forward declarations
class LoginConnectionManager;

class LoginClientConnection : public BaseClientConnection
{
public:
    // Login-specific connection states
    enum class LoginState
    {
        CONNECTED,        // Just connected, no encryption
        INIT_SENT,        // Init packet sent, awaiting auth
        BLOWFISH_READY,   // Blowfish key sent, ready for login packets
        AUTHENTICATED,    // Successfully logged in
        SERVER_LIST_SENT, // Server list sent, awaiting selection
        PLAY_OK_SENT,     // Play OK sent, ready for game server
        DISCONNECTED      // Connection closed
    };

    // Constructor
    LoginClientConnection(boost::asio::ip::tcp::socket socket,
                          boost::asio::io_context &io_context,
                          LoginConnectionManager *manager = nullptr);

    // Virtual destructor
    virtual ~LoginClientConnection() = default;

public:
    // Login-specific packet sending methods
    void send_init_packet(const ScrambledRSAKeyPair &rsa_pair,
                          const std::vector<uint8_t> &blowfish_key);
    void send_login_fail(uint8_t reason = 0x01);
    void send_server_list();
    void send_play_ok();

    // Login-specific state management
    void set_login_state(LoginState new_state);
    LoginState get_login_state() const { return login_state_.load(); }
    bool is_login_state(LoginState expected_state) const { return get_login_state() == expected_state; }

    // Login-specific session management
    void set_session_key(const SessionKey &key) { session_key_ = key; }
    const SessionKey &get_session_key() const { return session_key_; }

    // RSA key management
    void set_rsa_key_pair(const ScrambledRSAKeyPair &rsa_pair) { rsa_pair_ = &rsa_pair; }
    const ScrambledRSAKeyPair *get_rsa_key_pair() const { return rsa_pair_; }

protected:
    // Implementation of virtual methods from BaseClientConnection
    void handle_complete_packet(std::vector<uint8_t> packet_data) override;
    bool validate_state_transition(State from, State to) const override;

    // Login-specific encryption handling
    bool decrypt_incoming_packet(std::vector<uint8_t> &packet_data) override;
    void encrypt_outgoing_packet(std::vector<uint8_t> &packet_data) override;

    // Login-specific state transition validation
    bool validate_login_state_transition(LoginState from, LoginState to) const;

private:
    // Login-specific state
    std::atomic<LoginState> login_state_{LoginState::CONNECTED};

    // Login-specific encryption state (only login encryption)
    std::unique_ptr<LoginEncryption> login_encryption_;
    std::vector<uint8_t> blowfish_key_;

    // Login-specific session information
    SessionKey session_key_;

    // RSA key pair for this connection
    const ScrambledRSAKeyPair *rsa_pair_ = nullptr;

    // Login-specific packet handlers
    void handle_auth_login_packet(std::shared_ptr<AuthLoginPacket> packet);
    void handle_auth_gg_packet(std::shared_ptr<RequestAuthGG> packet);

    // Helper method to send raw init packet data
    void send_init_packet_raw(const std::vector<uint8_t> &packet_data);

    // L2 packet framing helpers (login-specific)
    void add_blowfish_padding(std::vector<uint8_t> &packet_data);

    // Encryption management (internal - login connection knows what encryption to use)
    void enable_encryption();

    // Login-specific disconnect handling
    void on_disconnect() override;
};

// Utility function for login state management
const char *login_state_to_string(LoginClientConnection::LoginState state);