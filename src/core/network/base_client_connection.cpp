#include "base_client_connection.hpp"
#include "base_connection_manager.hpp"
#include <iostream>
#include <iomanip>
#include <random>

// =============================================================================
// Constructor and Destructor
// =============================================================================

BaseClientConnection::BaseClientConnection(boost::asio::ip::tcp::socket socket,
                                           boost::asio::io_context &io_context,
                                           BaseConnectionManager *manager)
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

BaseClientConnection::~BaseClientConnection()
{
    cleanup_connection();
    log_connection_event("Connection destroyed");
}

// =============================================================================
// Connection Lifecycle
// =============================================================================

void BaseClientConnection::start()
{
    if (!is_connected())
    {
        return;
    }

    log_connection_event("Starting connection");

    // Start reading packets
    do_read();
}

void BaseClientConnection::disconnect()
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

void BaseClientConnection::force_disconnect()
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

void BaseClientConnection::set_state(State new_state)
{
    State old_state = connection_state_.load();

    if (old_state == new_state)
    {
        return;
    }

    // No validation here - derived classes handle their own state validation
    connection_state_.store(new_state);
    log_connection_event("State changed: " + std::string(state_to_string(old_state)) +
                         " -> " + std::string(state_to_string(new_state)));

    // Handle state-specific logic
    if (new_state == State::DISCONNECTED)
    {
        is_connected_.store(false);
        on_disconnect();
    }
}

// State validation is now handled by derived classes

// =============================================================================
// Packet I/O
// =============================================================================

void BaseClientConnection::send_packet(std::unique_ptr<SendablePacket> packet)
{
    if (!is_connected() || !packet)
    {
        return;
    }

    try
    {
        // Serialize the packet with 4-byte padding for checksum compatibility
        auto packet_data = packet->serialize(true, 4);
        send_raw_packet(packet_data);
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error serializing packet: " + std::string(e.what()));
        force_disconnect();
    }
}

void BaseClientConnection::send_raw_packet(const std::vector<uint8_t> &packet_data)
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
// Generic Connection Management (encryption handled by derived classes)
// =============================================================================

// =============================================================================
// Async I/O Implementation (shared implementation)
// =============================================================================

void BaseClientConnection::do_read()
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

void BaseClientConnection::handle_read(const boost::system::error_code &error, size_t bytes_transferred)
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

void BaseClientConnection::process_read_data(size_t bytes_available)
{
    const uint8_t *data = read_buffer_.data();
    size_t processed = 0;

    while (processed < bytes_available)
    {
        size_t consumed = 0;

        if (reading_header_)
        {
            if (try_read_packet_header(data + processed, bytes_available - processed, consumed))
            {
                reading_header_ = false;
            }
        }
        else
        {
            std::vector<uint8_t> complete_packet;
            if (try_read_packet_body(data + processed, bytes_available - processed, consumed, complete_packet))
            {
                reading_header_ = true;
                expected_packet_size_ = 0;
                partial_packet_buffer_.clear();

                // Derived classes handle encryption setup

                // Let derived class handle the complete packet
                handle_complete_packet(std::move(complete_packet));
            }
        }

        if (consumed == 0)
        {
            break;
        }

        processed += consumed;
    }
}

void BaseClientConnection::do_write(std::shared_ptr<std::vector<uint8_t>> data)
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

void BaseClientConnection::handle_write(const boost::system::error_code &error, size_t bytes_transferred,
                                        std::shared_ptr<std::vector<uint8_t>> data)
{
    if (error)
    {
        handle_connection_error(error);
        return;
    }

    log_connection_event("Sent packet: " + std::to_string(bytes_transferred) + " bytes");
}

// =============================================================================
// Packet Processing (basic implementation - derived classes handle encryption)
// =============================================================================

std::vector<uint8_t> BaseClientConnection::prepare_packet_for_transmission(const std::vector<uint8_t> &packet_data)
{
    // Step 1: Extract content only (remove the length header from serialize())
    std::vector<uint8_t> content_only;
    if (packet_data.size() >= 2)
    {
        content_only.assign(packet_data.begin() + 2, packet_data.end());
    }
    else
    {
        throw std::runtime_error("Packet data too small to contain header");
    }

    // Step 2: Let derived class handle encryption (virtual method)
    encrypt_outgoing_packet(content_only);

    // Step 3: Add L2 packet length header (2 bytes, little-endian)
    uint16_t total_length = static_cast<uint16_t>(content_only.size() + PACKET_SIZE_BYTES);

    std::vector<uint8_t> final_data;
    final_data.reserve(total_length);

    // Add length header (includes header size in total)
    final_data.push_back(static_cast<uint8_t>(total_length & 0xFF));        // Low byte
    final_data.push_back(static_cast<uint8_t>((total_length >> 8) & 0xFF)); // High byte

    // Add processed packet data
    final_data.insert(final_data.end(), content_only.begin(), content_only.end());

    return final_data;
}

// =============================================================================
// L2 Packet Framing Helpers (shared implementation)
// =============================================================================

bool BaseClientConnection::try_read_packet_header(const uint8_t *data, size_t available_bytes, size_t &consumed)
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

bool BaseClientConnection::try_read_packet_body(const uint8_t *data, size_t available_bytes, size_t &consumed,
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
// Utility Methods (shared implementation)
// =============================================================================

void BaseClientConnection::log_connection_event(const std::string &event) const
{
    std::cout << "[Connection " << remote_address_ << "] " << event << std::endl;
}

void BaseClientConnection::handle_connection_error(const boost::system::error_code &error)
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

void BaseClientConnection::cleanup_connection()
{
    is_connected_.store(false);

    // Clear buffers
    read_buffer_.clear();
    partial_packet_buffer_.clear();
}

// =============================================================================
// Utility Functions
// =============================================================================

const char *state_to_string(BaseClientConnection::State state)
{
    switch (state)
    {
    case BaseClientConnection::State::CONNECTED:
        return "CONNECTED";
    case BaseClientConnection::State::DISCONNECTED:
        return "DISCONNECTED";
    }
    return "UNKNOWN";
}