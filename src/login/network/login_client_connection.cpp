#include "login_client_connection.hpp"
#include "login_connection_manager.hpp"
#include "../packets/responses/login_ok_response.hpp"
#include "../packets/responses/auth_gg_response.hpp"
#include "../packets/responses/server_list_response.hpp"
#include "../server/game_server_manager.hpp"
#include "../../core/encryption/l2_checksum.hpp"
#include <iostream>
#include <ctime>

// =============================================================================
// Constructor
// =============================================================================

LoginClientConnection::LoginClientConnection(boost::asio::ip::tcp::socket socket,
                                             boost::asio::io_context &io_context,
                                             LoginConnectionManager *manager)
    : BaseClientConnection(std::move(socket), io_context, manager)
{
    log_connection_event("LoginClientConnection created");
}

// =============================================================================
// Virtual Method Implementations
// =============================================================================

void LoginClientConnection::send_init_packet(const ScrambledRSAKeyPair &rsa_pair,
                                             const std::vector<uint8_t> &blowfish_key)
{
    if (!is_login_state(LoginState::CONNECTED))
    {
        log_connection_event("Cannot send init packet in current state");
        return;
    }

    try
    {
        // Store RSA key pair and blowfish key for this connection
        set_rsa_key_pair(rsa_pair);
        blowfish_key_ = blowfish_key;

        // Create init packet using login-specific factory
        auto init_packet = PacketFactory::createInitPacket(session_id_, rsa_pair, blowfish_key);
        auto packet_data = init_packet->serialize();

        if (packet_data.empty())
        {
            log_connection_event("ERROR: InitPacket serialize() returned empty data!");
            force_disconnect();
            return;
        }

        // Send init packet as raw data (no encryption for init packet)
        send_init_packet_raw(packet_data);

        set_login_state(LoginState::INIT_SENT);
        log_connection_event("Init packet sent");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error sending init packet: " + std::string(e.what()));
        force_disconnect();
    }
}

void LoginClientConnection::send_login_fail(uint8_t reason)
{
    // TODO: Implement LoginFail packet
    log_connection_event("Login failed with reason: " + std::to_string(reason));
    force_disconnect();
}

void LoginClientConnection::send_server_list()
{
    if (!is_login_state(LoginState::AUTHENTICATED))
    {
        log_connection_event("Cannot send server list - client not authenticated");
        return;
    }

    try
    {
        auto* game_server_manager = get_game_server_manager();
        if (!game_server_manager)
        {
            log_connection_event("GameServerManager not available");
            send_login_fail(0x01);
            return;
        }

        // Get the server list
        auto servers = game_server_manager->getServerList();
        
        // Create and send server list response
        auto server_list_response = PacketFactory::createServerListResponse(servers);
        send_packet(std::move(server_list_response));

        set_login_state(LoginState::SERVER_LIST_SENT);
        log_connection_event("Server list sent with " + std::to_string(servers.size()) + " servers");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error sending server list: " + std::string(e.what()));
        send_login_fail(0x01);
    }
}

void LoginClientConnection::send_play_ok()
{
    // TODO: Implement PlayOk packet
    log_connection_event("Play OK requested (not implemented)");
}

void LoginClientConnection::handle_complete_packet(std::vector<uint8_t> packet_data)
{
    try
    {
        // Enable encryption after first client packet if needed
        if (is_login_state(LoginState::INIT_SENT) && !login_encryption_)
        {
            enable_encryption();
            set_login_state(LoginState::BLOWFISH_READY);
            log_connection_event("Login encryption enabled (after first packet)");
        }

        // Decrypt incoming packet
        if (!decrypt_incoming_packet(packet_data))
        {
            log_connection_event("Failed to decrypt incoming packet");
            force_disconnect();
            return;
        }

        // Verify checksum if login encryption is enabled
        if (login_encryption_)
        {
            if (!L2Checksum::remove_and_verify_checksum(packet_data))
            {
                log_connection_event("Packet checksum verification failed");
                force_disconnect();
                return;
            }
        }

        // Create packet from login-specific factory
        if (rsa_pair_)
        {
            auto packet = PacketFactory::createFromClientData(packet_data, *rsa_pair_);

            if (packet)
            {
                uint8_t packet_id = packet->getPacketId();

                // Handle different packet types
                switch (packet_id)
                {
                case 0x00: // RequestAuthLogin
                    if (auto auth_packet = dynamic_cast<AuthLoginPacket *>(packet.get()))
                    {
                        handle_auth_login_packet(std::shared_ptr<AuthLoginPacket>(auth_packet, [](AuthLoginPacket *) {}));
                    }
                    else
                    {
                        log_connection_event("Failed to cast AuthLogin packet");
                    }
                    break;

                case 0x07: // RequestAuthGG (GameGuard)
                    if (auto auth_gg_packet = dynamic_cast<RequestAuthGG *>(packet.get()))
                    {
                        handle_auth_gg_packet(std::shared_ptr<RequestAuthGG>(auth_gg_packet, [](RequestAuthGG *) {}));
                    }
                    else
                    {
                        log_connection_event("Failed to cast AuthGG packet");
                    }
                    break;

                case 0x05: // RequestServerList
                    if (auto server_list_packet = dynamic_cast<RequestServerList *>(packet.get()))
                    {
                        handle_request_server_list_packet(std::shared_ptr<RequestServerList>(server_list_packet, [](RequestServerList *) {}));
                    }
                    else
                    {
                        log_connection_event("Failed to cast RequestServerList packet");
                    }
                    break;

                case 0x02: // RequestGSLogin
                    log_connection_event("Received game server login");
                    send_play_ok();
                    break;

                default:
                    log_connection_event("Received unknown packet ID 0x" + std::to_string(packet_id));
                    break;
                }
            }
            else
            {
                log_connection_event("Failed to create packet from factory");
            }
        }
        else
        {
            log_connection_event("No RSA key pair available for packet decryption");
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error processing packet: " + std::string(e.what()));
        force_disconnect();
    }
}

bool LoginClientConnection::validate_state_transition(State from, State to) const
{
    // Handle basic state transitions (since base class no longer validates)
    // Allow transition to DISCONNECTED from any state
    if (to == State::DISCONNECTED)
    {
        return true;
    }

    // For base states, only allow CONNECTED -> DISCONNECTED
    switch (from)
    {
    case State::CONNECTED:
        return to == State::DISCONNECTED;
    case State::DISCONNECTED:
        return false; // Terminal state
    }

    return false;
}

bool LoginClientConnection::validate_login_state_transition(LoginState from, LoginState to) const
{
    // Allow transition to DISCONNECTED from any state
    if (to == LoginState::DISCONNECTED)
    {
        return true;
    }

    // Define valid state transitions for login server
    switch (from)
    {
    case LoginState::CONNECTED:
        return to == LoginState::INIT_SENT;

    case LoginState::INIT_SENT:
        return to == LoginState::BLOWFISH_READY;

    case LoginState::BLOWFISH_READY:
        return to == LoginState::AUTHENTICATED;

    case LoginState::AUTHENTICATED:
        return to == LoginState::SERVER_LIST_SENT;

    case LoginState::SERVER_LIST_SENT:
        return to == LoginState::PLAY_OK_SENT;

    case LoginState::PLAY_OK_SENT:
        return false; // Terminal state for login - ready for game server handoff

    case LoginState::DISCONNECTED:
        return false; // Terminal state
    }

    return false;
}

// =============================================================================
// Private Methods
// =============================================================================

void LoginClientConnection::handle_auth_login_packet(std::shared_ptr<AuthLoginPacket> packet)
{
    log_connection_event("Received login request - User: " + packet->getUsername());

    // TODO: Validate credentials against database
    // For now, accept any login and generate session keys

    // Generate session key (for demo purposes, using simple values)
    // TODO: In production, these should be cryptographically random
    int32_t login_ok1 = static_cast<int32_t>(std::time(nullptr));
    int32_t login_ok2 = static_cast<int32_t>(std::time(nullptr) ^ 0xDEADBEEF);
    int32_t play_ok1 = static_cast<int32_t>(std::time(nullptr) ^ 0xCAFEBABE);
    int32_t play_ok2 = static_cast<int32_t>(std::time(nullptr) ^ 0xFEEDFACE);

    SessionKey sessionKey(play_ok1, play_ok2, login_ok1, login_ok2);

    // Store session information
    set_account_name(packet->getUsername());
    set_login_state(LoginState::AUTHENTICATED);

    // Send LoginOk response
    auto login_ok_response = PacketFactory::createLoginOkResponse(sessionKey);
    send_packet(std::move(login_ok_response));

    log_connection_event("Login successful, LoginOk response sent");
}

void LoginClientConnection::handle_auth_gg_packet(std::shared_ptr<RequestAuthGG> packet)
{
    log_connection_event("Received GameGuard auth - Session ID: " + std::to_string(packet->getSessionId()));

    // Validate session ID matches connection's session ID
    if (packet->getSessionId() != get_session_id())
    {
        log_connection_event("AuthGG session ID mismatch - Expected: " + std::to_string(get_session_id()) +
                             ", Got: " + std::to_string(packet->getSessionId()));

        // TODO: Send login fail packet (matches Rust behavior)
        force_disconnect();
        return;
    }

    // Create and send AuthGG response
    auto auth_gg_response = PacketFactory::createAuthGGResponse(get_session_id());
    send_packet(std::move(auth_gg_response));

    log_connection_event("AuthGG validated and response sent");
}

void LoginClientConnection::handle_request_server_list_packet(std::shared_ptr<RequestServerList> packet)
{
    log_connection_event("Received server list request - LoginOk1: " + std::to_string(packet->getLoginOk1()) +
                         ", LoginOk2: " + std::to_string(packet->getLoginOk2()));

    // Validate that client is authenticated
    if (!is_login_state(LoginState::AUTHENTICATED))
    {
        log_connection_event("Server list requested but client not authenticated");
        send_login_fail(0x01);
        return;
    }

    // TODO: Validate the loginOk values against stored session if needed
    // For now, just send the server list
    send_server_list();
}

GameServerManager* LoginClientConnection::get_game_server_manager() const
{
    // Get the game server manager from our connection manager
    if (auto* login_manager = dynamic_cast<LoginConnectionManager*>(manager_))
    {
        return login_manager->get_game_server_manager();
    }
    return nullptr;
}

void LoginClientConnection::send_init_packet_raw(const std::vector<uint8_t> &packet_data)
{
    if (!is_connected())
    {
        return;
    }

    try
    {
        // Extract raw content (skip first 2 bytes which are the length header)
        std::vector<uint8_t> raw_content;
        if (packet_data.size() >= 2)
        {
            raw_content.assign(packet_data.begin() + 2, packet_data.end());
        }
        else
        {
            log_connection_event("ERROR: packet_data too small to contain header");
            return;
        }

        std::vector<uint8_t> final_data;

        // Add ONLY the L2 length header (2 bytes little-endian)
        uint16_t total_length = static_cast<uint16_t>(raw_content.size() + PACKET_SIZE_BYTES);
        final_data.push_back(static_cast<uint8_t>(total_length & 0xFF));
        final_data.push_back(static_cast<uint8_t>((total_length >> 8) & 0xFF));

        // Add packet data (UNTOUCHED - no encryption, no checksum, no padding)
        final_data.insert(final_data.end(), raw_content.begin(), raw_content.end());

        // Send directly to socket (bypass all processing)
        auto data_ptr = std::make_shared<std::vector<uint8_t>>(std::move(final_data));
        do_write(data_ptr);

        log_connection_event("Raw Init packet sent: " + std::to_string(data_ptr->size()) + " bytes");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error sending raw init packet: " + std::string(e.what()));
        force_disconnect();
    }
}

void LoginClientConnection::on_disconnect()
{
    set_login_state(LoginState::DISCONNECTED);

    // Clean up login-specific resources
    login_encryption_.reset();
    blowfish_key_.clear();
    rsa_pair_ = nullptr;

    log_connection_event("LoginClientConnection disconnected");
}

// =============================================================================
// Login-Specific Encryption Management
// =============================================================================

void LoginClientConnection::enable_encryption()
{
    try
    {
        // Login client connection only uses blowfish encryption for login phase
        if (!login_encryption_ && !blowfish_key_.empty())
        {
            login_encryption_ = std::make_unique<LoginEncryption>(blowfish_key_);
            log_connection_event("Login encryption enabled");
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error enabling encryption: " + std::string(e.what()));
        force_disconnect();
    }
}

// =============================================================================
// Login-Specific Packet Processing
// =============================================================================

bool LoginClientConnection::decrypt_incoming_packet(std::vector<uint8_t> &packet_data)
{
    try
    {
        if (login_encryption_)
        {
            return login_encryption_->decrypt(packet_data);
        }

        // No encryption enabled yet (first packet)
        return true;
    }
    catch (const std::exception &e)
    {
        log_connection_event("Decryption error: " + std::string(e.what()));
        return false;
    }
}

void LoginClientConnection::encrypt_outgoing_packet(std::vector<uint8_t> &packet_data)
{
    try
    {
        // Add checksum before encryption (only for login encryption)
        if (login_encryption_)
        {
            L2Checksum::add_checksum(packet_data);

            // Add Blowfish padding for login encryption (8-byte alignment required)
            add_blowfish_padding(packet_data);

            // Encrypt with login encryption
            login_encryption_->encrypt(packet_data);
        }
        // If no encryption, packet remains unencrypted (like init packet)
    }
    catch (const std::exception &e)
    {
        log_connection_event("Encryption error: " + std::string(e.what()));
        throw;
    }
}

void LoginClientConnection::add_blowfish_padding(std::vector<uint8_t> &packet_data)
{
    size_t current_size = packet_data.size();
    size_t padding_needed = (8 - (current_size % 8)) % 8;

    if (padding_needed > 0)
    {
        packet_data.resize(current_size + padding_needed, 0x00);
    }
}

// =============================================================================
// Login State Management
// =============================================================================

void LoginClientConnection::set_login_state(LoginState new_state)
{
    LoginState old_state = login_state_.load();

    if (old_state == new_state)
    {
        return;
    }

    if (!validate_login_state_transition(old_state, new_state))
    {
        log_connection_event("Invalid login state transition from " +
                             std::string(login_state_to_string(old_state)) +
                             " to " + std::string(login_state_to_string(new_state)));
        return;
    }

    login_state_.store(new_state);
    log_connection_event("Login state changed: " + std::string(login_state_to_string(old_state)) +
                         " -> " + std::string(login_state_to_string(new_state)));

    // Handle login state-specific logic
    if (new_state == LoginState::DISCONNECTED)
    {
        set_state(State::DISCONNECTED);
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

const char *login_state_to_string(LoginClientConnection::LoginState state)
{
    switch (state)
    {
    case LoginClientConnection::LoginState::CONNECTED:
        return "CONNECTED";
    case LoginClientConnection::LoginState::INIT_SENT:
        return "INIT_SENT";
    case LoginClientConnection::LoginState::BLOWFISH_READY:
        return "BLOWFISH_READY";
    case LoginClientConnection::LoginState::AUTHENTICATED:
        return "AUTHENTICATED";
    case LoginClientConnection::LoginState::SERVER_LIST_SENT:
        return "SERVER_LIST_SENT";
    case LoginClientConnection::LoginState::PLAY_OK_SENT:
        return "PLAY_OK_SENT";
    case LoginClientConnection::LoginState::DISCONNECTED:
        return "DISCONNECTED";
    }
    return "UNKNOWN";
}