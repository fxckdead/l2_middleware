#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <functional>
#include <cstdint>
#include <string>
#include <atomic>

#include "../packets/packet.hpp"

// Forward declarations
class BaseConnectionManager;

class BaseClientConnection : public std::enable_shared_from_this<BaseClientConnection>
{
public:
    // Basic connection states (generic for any TCP connection)
    enum class State
    {
        CONNECTED,   // Just connected
        DISCONNECTED // Connection closed
    };

    // L2 packet framing constants (matching Rust implementation)
    static constexpr size_t PACKET_SIZE_BYTES = 2;
    static constexpr size_t MAX_PACKET_SIZE = 8192; // Reasonable max packet size
    static constexpr size_t READ_BUFFER_SIZE = 4096;

protected:
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

    // Generic session information
    std::string account_name_;
    int32_t session_id_;

    // Connection manager reference
    BaseConnectionManager *manager_ = nullptr;

public:
    // Constructor
    BaseClientConnection(boost::asio::ip::tcp::socket socket,
                         boost::asio::io_context &io_context,
                         BaseConnectionManager *manager = nullptr);

    // Virtual destructor for proper inheritance
    virtual ~BaseClientConnection();

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

    // State validation will be implemented by derived classes

    // Packet I/O (main interface)
    void send_packet(std::unique_ptr<SendablePacket> packet);
    void send_raw_packet(const std::vector<uint8_t> &packet_data);

    // Generic connection management (derived classes handle encryption)

    // Basic session management (generic)
    void set_account_name(const std::string &name) { account_name_ = name; }
    void set_session_id(int32_t id) { session_id_ = id; }

    const std::string &get_account_name() const { return account_name_; }
    int32_t get_session_id() const { return session_id_; }

protected:
    // Virtual methods that derived classes must implement
    virtual void handle_complete_packet(std::vector<uint8_t> packet_data) = 0;
    virtual bool validate_state_transition(State from, State to) const = 0;

    // Async I/O methods (shared implementation)
    void do_read();
    void handle_read(const boost::system::error_code &error, size_t bytes_transferred);
    void process_read_data(size_t bytes_available);

    void do_write(std::shared_ptr<std::vector<uint8_t>> data);
    void handle_write(const boost::system::error_code &error, size_t bytes_transferred,
                      std::shared_ptr<std::vector<uint8_t>> data);

    // Packet processing (basic implementation - derived classes handle encryption)
    virtual bool decrypt_incoming_packet(std::vector<uint8_t> &packet_data) { return true; } // No encryption by default
    virtual void encrypt_outgoing_packet(std::vector<uint8_t> &packet_data) {}               // No encryption by default
    std::vector<uint8_t> prepare_packet_for_transmission(const std::vector<uint8_t> &packet_data);

    // L2 packet framing helpers (shared implementation)
    bool try_read_packet_header(const uint8_t *data, size_t available_bytes, size_t &consumed);
    bool try_read_packet_body(const uint8_t *data, size_t available_bytes, size_t &consumed,
                              std::vector<uint8_t> &complete_packet);

    // Utility methods (shared implementation)
    void log_connection_event(const std::string &event) const;
    void handle_connection_error(const boost::system::error_code &error);
    void cleanup_connection();

private:
    // Virtual callback for handling disconnection (called by cleanup)
    virtual void on_disconnect() {}
};

// Utility functions
const char *state_to_string(BaseClientConnection::State state);
bool is_valid_state_transition(BaseClientConnection::State from, BaseClientConnection::State to);