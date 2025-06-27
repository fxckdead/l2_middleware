#include "client_connection.hpp"
#include "init_packet.hpp"
#include "l2_checksum.hpp"
#include <iostream>
#include <iomanip>
#include <random>

// Forward declaration of ConnectionManager for now
class ConnectionManager;

// =============================================================================
// Constructor and Destructor
// =============================================================================

ClientConnection::ClientConnection(boost::asio::ip::tcp::socket socket,
                                   boost::asio::io_context &io_context,
                                   ConnectionManager *manager)
    : socket_(std::move(socket)), io_context_(io_context), manager_(manager)
{
    // Initialize read buffer
    read_buffer_.resize(READ_BUFFER_SIZE);

    // Get remote address for logging
    try
    {
        auto endpoint = socket_.remote_endpoint();
        remote_address_ = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
    }
    catch (const std::exception &e)
    {
        remote_address_ = "unknown";
    }

    // Generate random session ID
    std::random_device rd;
    session_id_ = static_cast<int32_t>(rd());

    log_connection_event("Connection created");
}

ClientConnection::~ClientConnection()
{
    cleanup_connection();
    log_connection_event("Connection destroyed");
}

// =============================================================================
// Connection Lifecycle
// =============================================================================

void ClientConnection::start()
{
    if (!is_connected())
    {
        return;
    }

    log_connection_event("Starting connection");

    // Start reading packets
    do_read();
}

void ClientConnection::disconnect()
{
    if (!is_connected())
    {
        return;
    }

    log_connection_event("Graceful disconnect initiated");
    set_state(State::DISCONNECTED);

    // Close socket gracefully
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);

    cleanup_connection();
}

void ClientConnection::force_disconnect()
{
    if (!is_connected())
    {
        return;
    }

    log_connection_event("Force disconnect initiated");
    set_state(State::DISCONNECTED);

    // Close socket immediately
    boost::system::error_code ec;
    socket_.close(ec);

    cleanup_connection();
}

// =============================================================================
// State Management
// =============================================================================

void ClientConnection::set_state(State new_state)
{
    State old_state = connection_state_.load();

    if (old_state == new_state)
    {
        return;
    }

    if (!validate_state_transition(old_state, new_state))
    {
        log_connection_event("Invalid state transition from " +
                             std::string(state_to_string(old_state)) +
                             " to " + std::string(state_to_string(new_state)));
        return;
    }

    connection_state_.store(new_state);
    log_connection_event("State changed: " + std::string(state_to_string(old_state)) +
                         " -> " + std::string(state_to_string(new_state)));

    // Handle state-specific logic
    if (new_state == State::DISCONNECTED)
    {
        is_connected_.store(false);
        if (disconnect_handler_)
        {
            disconnect_handler_(this);
        }
    }
}

// =============================================================================
// Packet I/O
// =============================================================================

void ClientConnection::send_packet(std::unique_ptr<SendablePacket> packet)
{
    if (!is_connected() || !packet)
    {
        return;
    }

    try
    {
        // Serialize the packet
        auto packet_data = packet->serialize();
        send_raw_packet(packet_data);
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error serializing packet: " + std::string(e.what()));
        force_disconnect();
    }
}

void ClientConnection::send_raw_packet(const std::vector<uint8_t> &packet_data)
{
    if (!is_connected())
    {
        return;
    }

    try
    {
        // Prepare packet for transmission (encrypt + add header)
        auto transmission_data = prepare_packet_for_transmission(packet_data);

        // Create shared pointer for async write
        auto data_ptr = std::make_shared<std::vector<uint8_t>>(std::move(transmission_data));

        // Send asynchronously
        do_write(data_ptr);
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error sending packet: " + std::string(e.what()));
        force_disconnect();
    }
}

// =============================================================================
// High-level Packet Sending
// =============================================================================

void ClientConnection::send_init_packet(const ScrambledRSAKeyPair &rsa_pair,
                                        const std::vector<uint8_t> &blowfish_key)
{
    if (!is_state(State::CONNECTED))
    {
        log_connection_event("Cannot send init packet in current state");
        return;
    }

    try
    {
        // Store RSA key pair and blowfish key for this connection
        set_rsa_key_pair(rsa_pair);
        blowfish_key_ = blowfish_key;

        // Create and send init packet
        auto init_packet = std::make_unique<InitPacket>(session_id_, rsa_pair, blowfish_key);
        send_packet(std::move(init_packet));

        set_state(State::INIT_SENT);
        log_connection_event("Init packet sent");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error sending init packet: " + std::string(e.what()));
        force_disconnect();
    }
}

void ClientConnection::send_login_fail(uint8_t reason)
{
    // TODO: Implement LoginFail packet
    log_connection_event("Login failed with reason: " + std::to_string(reason));
    force_disconnect();
}

void ClientConnection::send_server_list()
{
    // TODO: Implement ServerList packet
    log_connection_event("Server list requested (not implemented)");
}

void ClientConnection::send_play_ok()
{
    // TODO: Implement PlayOk packet
    log_connection_event("Play OK requested (not implemented)");
}

// =============================================================================
// Encryption Management
// =============================================================================

void ClientConnection::enable_login_encryption(const std::vector<uint8_t> &blowfish_key)
{
    try
    {
        login_encryption_ = std::make_unique<LoginEncryption>(blowfish_key);
        blowfish_key_ = blowfish_key;
        set_state(State::BLOWFISH_READY);
        log_connection_event("Login encryption enabled");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error enabling login encryption: " + std::string(e.what()));
        force_disconnect();
    }
}

void ClientConnection::enable_game_encryption(const std::vector<uint8_t> &game_key)
{
    try
    {
        game_encryption_ = std::make_unique<GameClientEncryption>(game_key);
        set_state(State::GAME_ENCRYPTED);
        log_connection_event("Game client encryption enabled");
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error enabling game encryption: " + std::string(e.what()));
        force_disconnect();
    }
}

// =============================================================================
// Async I/O Implementation (matching Rust connection.rs pattern)
// =============================================================================

void ClientConnection::do_read()
{
    if (!is_connected())
    {
        return;
    }

    auto self = shared_from_this();
    socket_.async_read_some(
        boost::asio::buffer(read_buffer_),
        [this, self](const boost::system::error_code &error, size_t bytes_transferred)
        {
            handle_read(error, bytes_transferred);
        });
}

void ClientConnection::handle_read(const boost::system::error_code &error, size_t bytes_transferred)
{
    if (error)
    {
        handle_connection_error(error);
        return;
    }

    if (bytes_transferred == 0)
    {
        log_connection_event("Client disconnected (0 bytes read)");
        disconnect();
        return;
    }

    try
    {
        // Process the received data
        process_read_data(bytes_transferred);

        // Continue reading if still connected
        if (is_connected())
        {
            do_read();
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error processing read data: " + std::string(e.what()));
        force_disconnect();
    }
}

void ClientConnection::process_read_data(size_t bytes_available)
{
    const uint8_t *data = read_buffer_.data();
    size_t processed = 0;

    while (processed < bytes_available)
    {
        size_t consumed = 0;

        if (reading_header_)
        {
            // Try to read packet header (2 bytes)
            if (try_read_packet_header(data + processed, bytes_available - processed, consumed))
            {
                reading_header_ = false;
                // Enable encryption after init packet is sent
                if (is_state(State::INIT_SENT) && !login_encryption_)
                {
                    enable_login_encryption(blowfish_key_);
                }
            }
        }
        else
        {
            // Try to read packet body
            std::vector<uint8_t> complete_packet;
            if (try_read_packet_body(data + processed, bytes_available - processed, consumed, complete_packet))
            {
                reading_header_ = true;
                expected_packet_size_ = 0;
                partial_packet_buffer_.clear();

                // Process complete packet
                handle_complete_packet(std::move(complete_packet));
            }
        }

        if (consumed == 0)
        {
            // No progress made, need more data
            break;
        }

        processed += consumed;
    }
}

void ClientConnection::handle_complete_packet(std::vector<uint8_t> packet_data)
{
    try
    {
        // Decrypt incoming packet
        if (!decrypt_incoming_packet(packet_data))
        {
            log_connection_event("Failed to decrypt incoming packet");
            force_disconnect();
            return;
        }

        // Verify checksum if encryption is enabled
        if (login_encryption_ || game_encryption_)
        {
            if (!L2Checksum::remove_and_verify_checksum(packet_data))
            {
                log_connection_event("Packet checksum verification failed");
                force_disconnect();
                return;
            }
        }

        // Create packet from factory
        if (rsa_pair_)
        {
            auto packet = PacketFactory::createFromClientData(packet_data, *rsa_pair_);

            if (packet && packet_handler_)
            {
                packet_handler_(std::move(packet), this);
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

void ClientConnection::do_write(std::shared_ptr<std::vector<uint8_t>> data)
{
    if (!is_connected() || !data || data->empty())
    {
        return;
    }

    auto self = shared_from_this();
    boost::asio::async_write(
        socket_,
        boost::asio::buffer(*data),
        [this, self, data](const boost::system::error_code &error, size_t bytes_transferred)
        {
            handle_write(error, bytes_transferred, data);
        });
}

void ClientConnection::handle_write(const boost::system::error_code &error, size_t bytes_transferred,
                                    std::shared_ptr<std::vector<uint8_t>> data)
{
    if (error)
    {
        handle_connection_error(error);
        return;
    }

    // Log successful packet transmission
    log_connection_event("Sent packet: " + std::to_string(bytes_transferred) + " bytes");
}

// =============================================================================
// Packet Processing
// =============================================================================

bool ClientConnection::decrypt_incoming_packet(std::vector<uint8_t> &packet_data)
{
    try
    {
        if (game_encryption_)
        {
            return game_encryption_->decrypt(packet_data);
        }
        else if (login_encryption_)
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

void ClientConnection::encrypt_outgoing_packet(std::vector<uint8_t> &packet_data)
{
    try
    {
        // Add checksum before encryption
        if (login_encryption_ || game_encryption_)
        {
            L2Checksum::add_checksum(packet_data);

            // Add Blowfish padding for login encryption (8-byte alignment required)
            if (login_encryption_)
            {
                add_blowfish_padding(packet_data);
            }
        }

        if (game_encryption_)
        {
            game_encryption_->encrypt(packet_data);
        }
        else if (login_encryption_)
        {
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

// =============================================================================
// L2 Packet Framing Helpers
// =============================================================================

void ClientConnection::add_blowfish_padding(std::vector<uint8_t> &packet_data)
{
    /*
     * L2 Packet Framing with Blowfish Padding:
     * ┌─────────────┬──────────────────┬──────────────┐
     * │ Length (2)  │   Packet Data    │ Padding (0-7)│
     * │ Little-End  │   (Variable)     │   (Optional) │
     * └─────────────┴──────────────────┴──────────────┘
     *
     * Blowfish requires 8-byte alignment, so we pad with null bytes
     */
    size_t current_size = packet_data.size();
    size_t padding_needed = (8 - (current_size % 8)) % 8;

    if (padding_needed > 0)
    {
        packet_data.resize(current_size + padding_needed, 0x00);
    }
}

std::vector<uint8_t> ClientConnection::prepare_packet_for_transmission(const std::vector<uint8_t> &packet_data)
{
    /*
     * Complete L2 Packet Framing Implementation:
     * ┌─────────────┬───────────────────────────────────────┐
     * │ Length (2)  │           Packet Data                 │
     * │ Little-End  │ [Content + Checksum + Padding]        │
     * │             │ [Encrypted with Blowfish/GameCrypt]   │
     * └─────────────┴───────────────────────────────────────┘
     */

    std::vector<uint8_t> transmission_data = packet_data;

    // Step 1: Encrypt the packet (adds checksum + padding + encryption)
    encrypt_outgoing_packet(transmission_data);

    // Step 2: Add L2 packet length header (2 bytes, little-endian)
    uint16_t total_length = static_cast<uint16_t>(transmission_data.size() + PACKET_SIZE_BYTES);

    std::vector<uint8_t> final_data;
    final_data.reserve(total_length);

    // Add length header (includes header size in total)
    final_data.push_back(static_cast<uint8_t>(total_length & 0xFF));        // Low byte
    final_data.push_back(static_cast<uint8_t>((total_length >> 8) & 0xFF)); // High byte

    // Add encrypted packet data
    final_data.insert(final_data.end(), transmission_data.begin(), transmission_data.end());

    return final_data;
}

// =============================================================================
// Packet Framing (matching Rust read_packet logic)
// =============================================================================

bool ClientConnection::try_read_packet_header(const uint8_t *data, size_t available_bytes, size_t &consumed)
{
    size_t needed = PACKET_SIZE_BYTES - partial_packet_buffer_.size();
    size_t to_copy = std::min(needed, available_bytes);

    // Accumulate header bytes
    partial_packet_buffer_.insert(partial_packet_buffer_.end(), data, data + to_copy);
    consumed = to_copy;

    if (partial_packet_buffer_.size() == PACKET_SIZE_BYTES)
    {
        // Complete header received, extract packet size
        expected_packet_size_ = static_cast<uint16_t>(partial_packet_buffer_[0]) |
                                (static_cast<uint16_t>(partial_packet_buffer_[1]) << 8);

        // Validate packet size
        if (expected_packet_size_ < PACKET_SIZE_BYTES || expected_packet_size_ > MAX_PACKET_SIZE)
        {
            log_connection_event("Invalid packet size: " + std::to_string(expected_packet_size_));
            throw std::runtime_error("Invalid packet size");
        }

        // Calculate actual packet data size (excluding the 2-byte header)
        expected_packet_size_ -= PACKET_SIZE_BYTES;

        // Clear partial buffer for packet body
        partial_packet_buffer_.clear();
        return true;
    }

    return false;
}

bool ClientConnection::try_read_packet_body(const uint8_t *data, size_t available_bytes, size_t &consumed,
                                            std::vector<uint8_t> &complete_packet)
{
    size_t needed = expected_packet_size_ - partial_packet_buffer_.size();
    size_t to_copy = std::min(needed, available_bytes);

    // Accumulate packet body bytes
    partial_packet_buffer_.insert(partial_packet_buffer_.end(), data, data + to_copy);
    consumed = to_copy;

    if (partial_packet_buffer_.size() == expected_packet_size_)
    {
        // Complete packet received
        complete_packet = std::move(partial_packet_buffer_);
        return true;
    }

    return false;
}

// =============================================================================
// Utility Methods
// =============================================================================

void ClientConnection::log_connection_event(const std::string &event) const
{
    std::cout << "[Connection " << remote_address_ << "] " << event << std::endl;
}

void ClientConnection::handle_connection_error(const boost::system::error_code &error)
{
    if (error == boost::asio::error::eof)
    {
        log_connection_event("Client disconnected (EOF)");
        disconnect();
    }
    else if (error == boost::asio::error::connection_reset)
    {
        log_connection_event("Connection reset by peer");
        force_disconnect();
    }
    else if (error != boost::asio::error::operation_aborted)
    {
        log_connection_event("Connection error: " + error.message());
        force_disconnect();
    }
}

void ClientConnection::cleanup_connection()
{
    is_connected_.store(false);

    // Clear encryption objects
    login_encryption_.reset();
    game_encryption_.reset();

    // Clear buffers
    read_buffer_.clear();
    partial_packet_buffer_.clear();
    blowfish_key_.clear();
}

bool ClientConnection::validate_state_transition(State from, State to) const
{
    // Allow transition to DISCONNECTED from any state
    if (to == State::DISCONNECTED)
    {
        return true;
    }

    // Define valid state transitions
    switch (from)
    {
    case State::CONNECTED:
        return to == State::INIT_SENT;

    case State::INIT_SENT:
        return to == State::BLOWFISH_READY;

    case State::BLOWFISH_READY:
        return to == State::AUTHENTICATED;

    case State::AUTHENTICATED:
        return to == State::SERVER_LIST_SENT || to == State::GAME_ENCRYPTED;

    case State::SERVER_LIST_SENT:
        return to == State::PLAY_OK_SENT;

    case State::PLAY_OK_SENT:
        return to == State::GAME_ENCRYPTED;

    case State::GAME_ENCRYPTED:
        return false; // Terminal state (except disconnect)

    case State::DISCONNECTED:
        return false; // Terminal state
    }

    return false;
}

// =============================================================================
// Utility Functions
// =============================================================================

const char *state_to_string(ClientConnection::State state)
{
    switch (state)
    {
    case ClientConnection::State::CONNECTED:
        return "CONNECTED";
    case ClientConnection::State::INIT_SENT:
        return "INIT_SENT";
    case ClientConnection::State::BLOWFISH_READY:
        return "BLOWFISH_READY";
    case ClientConnection::State::AUTHENTICATED:
        return "AUTHENTICATED";
    case ClientConnection::State::GAME_ENCRYPTED:
        return "GAME_ENCRYPTED";
    case ClientConnection::State::SERVER_LIST_SENT:
        return "SERVER_LIST_SENT";
    case ClientConnection::State::PLAY_OK_SENT:
        return "PLAY_OK_SENT";
    case ClientConnection::State::DISCONNECTED:
        return "DISCONNECTED";
    }
    return "UNKNOWN";
}

bool is_valid_state_transition(ClientConnection::State from, ClientConnection::State to)
{
    // This is a standalone version of the validation logic
    if (to == ClientConnection::State::DISCONNECTED)
    {
        return true;
    }

    switch (from)
    {
    case ClientConnection::State::CONNECTED:
        return to == ClientConnection::State::INIT_SENT;

    case ClientConnection::State::INIT_SENT:
        return to == ClientConnection::State::BLOWFISH_READY;

    case ClientConnection::State::BLOWFISH_READY:
        return to == ClientConnection::State::AUTHENTICATED;

    case ClientConnection::State::AUTHENTICATED:
        return to == ClientConnection::State::SERVER_LIST_SENT ||
               to == ClientConnection::State::GAME_ENCRYPTED;

    case ClientConnection::State::SERVER_LIST_SENT:
        return to == ClientConnection::State::PLAY_OK_SENT;

    case ClientConnection::State::PLAY_OK_SENT:
        return to == ClientConnection::State::GAME_ENCRYPTED;

    case ClientConnection::State::GAME_ENCRYPTED:
    case ClientConnection::State::DISCONNECTED:
        return false;
    }

    return false;
}