#include "connection_manager.hpp"
#include "init_packet.hpp"
#include "auth_login_packet.hpp"
#include "packet_factory.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <random>
#include <ctime>

// =============================================================================
// Constructor and Destructor
// =============================================================================

ConnectionManager::ConnectionManager(boost::asio::io_context &io_context, const Config &config)
    : config_(config), io_context_(io_context)
{
    // Initialize RSA key manager with configured pool size
    rsa_manager_ = std::make_unique<RSAManager>(config_.rsa_key_pool_size);

    log_connection_event("ConnectionManager initialized with max " +
                         std::to_string(config_.max_connections) + " connections");
}

ConnectionManager::~ConnectionManager()
{
    disconnect_all();
    log_connection_event("ConnectionManager destroyed");
}

// =============================================================================
// Connection Lifecycle
// =============================================================================

ConnectionManager::ConnectionPtr ConnectionManager::create_connection(boost::asio::ip::tcp::socket socket)
{
    if (is_connection_limit_reached())
    {
        log_connection_event("Connection limit reached, rejecting new connection");
        return nullptr;
    }

    // Create new connection
    auto connection = std::make_shared<ClientConnection>(std::move(socket), io_context_, this);

    // Set up event handlers
    setup_connection_handlers(connection);

    return connection;
}

bool ConnectionManager::add_connection(ConnectionPtr connection)
{
    if (!connection || is_connection_limit_reached())
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(connections_mutex_);

    ConnectionId id = generate_connection_id();
    active_connections_[id] = connection;

    // Update statistics
    stats_.total_connections.fetch_add(1);
    stats_.active_connections.fetch_add(1);
    update_peak_connections();

    log_connection_event("Added connection " + std::to_string(id) +
                         " (" + connection->get_remote_address() + ")");

    // Send initial packets to new connection
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

        // Send init packet
        connection->send_init_packet(rsa_pair, blowfish_key);
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error initializing connection " + std::to_string(id) + ": " + e.what());
        remove_connection(id);
        return false;
    }

    return true;
}

void ConnectionManager::remove_connection(ConnectionId connection_id)
{
    ConnectionPtr connection;

    {
        std::lock_guard<std::mutex> lock(connections_mutex_);

        auto it = active_connections_.find(connection_id);
        if (it != active_connections_.end())
        {
            connection = it->second;
            active_connections_.erase(it);
            disconnecting_connections_.insert(connection_id);
        }
    }

    if (connection)
    {
        // Update statistics
        stats_.active_connections.fetch_sub(1);

        log_connection_event("Removed connection " + std::to_string(connection_id) +
                             " (" + connection->get_remote_address() + ")");

        // Disconnect the connection
        connection->disconnect();
    }
}

void ConnectionManager::remove_connection(ClientConnection *connection)
{
    if (!connection)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(connections_mutex_);

    for (auto it = active_connections_.begin(); it != active_connections_.end(); ++it)
    {
        if (it->second.get() == connection)
        {
            ConnectionId id = it->first;
            active_connections_.erase(it);
            disconnecting_connections_.insert(id);

            // Update statistics
            stats_.active_connections.fetch_sub(1);

            log_connection_event("Removed connection by pointer (" +
                                 connection->get_remote_address() + ")");
            break;
        }
    }
}

// =============================================================================
// Connection Queries
// =============================================================================

ConnectionManager::ConnectionPtr ConnectionManager::get_connection(ConnectionId connection_id) const
{
    std::lock_guard<std::mutex> lock(connections_mutex_);

    auto it = active_connections_.find(connection_id);
    return (it != active_connections_.end()) ? it->second : nullptr;
}

std::vector<ConnectionManager::ConnectionPtr> ConnectionManager::get_all_connections() const
{
    std::lock_guard<std::mutex> lock(connections_mutex_);

    std::vector<ConnectionPtr> connections;
    connections.reserve(active_connections_.size());

    for (const auto &pair : active_connections_)
    {
        connections.push_back(pair.second);
    }

    return connections;
}

std::vector<ConnectionManager::ConnectionPtr> ConnectionManager::get_connections_by_state(ClientConnection::State state) const
{
    std::lock_guard<std::mutex> lock(connections_mutex_);

    std::vector<ConnectionPtr> connections;

    for (const auto &pair : active_connections_)
    {
        if (pair.second->get_state() == state)
        {
            connections.push_back(pair.second);
        }
    }

    return connections;
}

// =============================================================================
// Connection Management
// =============================================================================

size_t ConnectionManager::get_connection_count() const
{
    std::lock_guard<std::mutex> lock(connections_mutex_);
    return active_connections_.size();
}

bool ConnectionManager::is_connection_limit_reached() const
{
    return get_connection_count() >= config_.max_connections;
}

void ConnectionManager::disconnect_all()
{
    std::vector<ConnectionPtr> connections;

    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        connections.reserve(active_connections_.size());

        for (const auto &pair : active_connections_)
        {
            connections.push_back(pair.second);
        }

        active_connections_.clear();
        disconnecting_connections_.clear();
    }

    // Disconnect all connections outside the lock
    for (auto &connection : connections)
    {
        connection->force_disconnect();
    }

    // Update statistics
    stats_.active_connections.store(0);

    log_connection_event("Disconnected all connections");
}

void ConnectionManager::cleanup_disconnected_connections()
{
    std::lock_guard<std::mutex> lock(connections_mutex_);

    // Remove connections that are marked as disconnecting
    for (auto id : disconnecting_connections_)
    {
        active_connections_.erase(id);
    }
    disconnecting_connections_.clear();

    // Also remove any connections that are in DISCONNECTED state
    for (auto it = active_connections_.begin(); it != active_connections_.end();)
    {
        if (!it->second->is_connected() || it->second->get_state() == ClientConnection::State::DISCONNECTED)
        {
            it = active_connections_.erase(it);
            stats_.active_connections.fetch_sub(1);
        }
        else
        {
            ++it;
        }
    }
}

// =============================================================================
// Statistics
// =============================================================================

void ConnectionManager::reset_stats()
{
    stats_.total_connections.store(0);
    stats_.peak_connections.store(get_connection_count());
    stats_.total_packets_sent.store(0);
    stats_.total_packets_received.store(0);
    stats_.total_bytes_sent.store(0);
    stats_.total_bytes_received.store(0);

    log_connection_event("Statistics reset");
}

void ConnectionManager::print_stats() const
{
    std::cout << "\n=== Connection Manager Statistics ===" << std::endl;
    std::cout << "Active connections: " << stats_.active_connections.load() << std::endl;
    std::cout << "Total connections: " << stats_.total_connections.load() << std::endl;
    std::cout << "Peak connections: " << stats_.peak_connections.load() << std::endl;
    std::cout << "Packets sent: " << stats_.total_packets_sent.load() << std::endl;
    std::cout << "Packets received: " << stats_.total_packets_received.load() << std::endl;
    std::cout << "Bytes sent: " << format_bytes(stats_.total_bytes_sent.load()) << std::endl;
    std::cout << "Bytes received: " << format_bytes(stats_.total_bytes_received.load()) << std::endl;
    std::cout << "Max connections: " << config_.max_connections << std::endl;
    std::cout << "RSA key pool size: " << config_.rsa_key_pool_size << std::endl;
    std::cout << "=========================================\n"
              << std::endl;
}

// =============================================================================
// Configuration
// =============================================================================

void ConnectionManager::set_max_connections(uint32_t max_connections)
{
    config_.max_connections = max_connections;
    log_connection_event("Max connections set to " + std::to_string(max_connections));
}

// =============================================================================
// RSA Key Management
// =============================================================================

const ScrambledRSAKeyPair &ConnectionManager::get_random_rsa_key() const
{
    return rsa_manager_->getRandomRSAKeyPair();
}

// =============================================================================
// Packet Broadcasting
// =============================================================================

void ConnectionManager::broadcast_packet(std::unique_ptr<SendablePacket> packet)
{
    if (!packet)
    {
        return;
    }

    auto connections = get_all_connections();

    for (auto &connection : connections)
    {
        if (connection->is_connected())
        {
            // Create a copy of the packet for each connection
            auto packet_copy = std::unique_ptr<SendablePacket>(packet.get()); // This needs better cloning
            connection->send_packet(std::move(packet_copy));
        }
    }

    stats_.total_packets_sent.fetch_add(connections.size());
}

void ConnectionManager::broadcast_to_state(std::unique_ptr<SendablePacket> packet, ClientConnection::State state)
{
    if (!packet)
    {
        return;
    }

    auto connections = get_connections_by_state(state);

    for (auto &connection : connections)
    {
        if (connection->is_connected())
        {
            // Create a copy of the packet for each connection
            auto packet_copy = std::unique_ptr<SendablePacket>(packet.get()); // This needs better cloning
            connection->send_packet(std::move(packet_copy));
        }
    }

    stats_.total_packets_sent.fetch_add(connections.size());
}

// =============================================================================
// Internal Helpers
// =============================================================================

ConnectionManager::ConnectionId ConnectionManager::generate_connection_id()
{
    return next_connection_id_.fetch_add(1);
}

void ConnectionManager::handle_connection_disconnect(ClientConnection *connection)
{
    remove_connection(connection);
}

void ConnectionManager::update_peak_connections()
{
    uint32_t current = stats_.active_connections.load();
    uint32_t peak = stats_.peak_connections.load();

    while (current > peak && !stats_.peak_connections.compare_exchange_weak(peak, current))
    {
        // Loop until we successfully update or current <= peak
    }
}

void ConnectionManager::log_connection_event(const std::string &event) const
{
    if (config_.enable_connection_logging)
    {
        std::cout << "[ConnectionManager] " << event << std::endl;
    }
}

void ConnectionManager::setup_connection_handlers(ConnectionPtr connection)
{
    // Set packet handler
    connection->set_packet_handler(
        [this](std::shared_ptr<ReadablePacket> packet, ClientConnection *conn)
        {
            handle_packet_from_connection(std::move(packet), conn);
        });

    // Set disconnect handler
    connection->set_disconnect_handler(
        [this](ClientConnection *conn)
        {
            handle_connection_disconnect(conn);
        });
}

void ConnectionManager::handle_packet_from_connection(std::shared_ptr<ReadablePacket> packet, ClientConnection *connection)
{
    if (!packet || !connection)
    {
        return;
    }

    stats_.total_packets_received.fetch_add(1);

    try
    {
        uint8_t packet_id = packet->getPacketId();

        // Handle different packet types
        switch (packet_id)
        {
        case 0x00: // RequestAuthLogin
        {
            if (auto auth_packet = std::dynamic_pointer_cast<AuthLoginPacket>(packet))
            {
                log_connection_event("Received login request from " + connection->get_remote_address() +
                                     " - User: " + auth_packet->getUsername());

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
                connection->set_account_name(auth_packet->getUsername());
                connection->set_state(ClientConnection::State::AUTHENTICATED);

                // Send LoginOk response
                auto login_ok_response = PacketFactory::createLoginOkResponse(sessionKey);
                connection->send_packet(std::move(login_ok_response));

                log_connection_event("Login successful, LoginOk response sent to " + connection->get_remote_address());
            }
            else
            {
                log_connection_event("Failed to cast AuthLogin packet from " + connection->get_remote_address());
            }
            break;
        }

        case 0x07: // RequestAuthGG (GameGuard)
        {
            if (auto auth_gg_packet = std::dynamic_pointer_cast<RequestAuthGG>(packet))
            {
                log_connection_event("Received GameGuard auth from " + connection->get_remote_address() +
                                     " - Session ID: " + std::to_string(auth_gg_packet->getSessionId()));

                // Validate session ID matches connection's session ID
                if (auth_gg_packet->getSessionId() != connection->get_session_id())
                {
                    log_connection_event("AuthGG session ID mismatch for " + connection->get_remote_address() +
                                         " - Expected: " + std::to_string(connection->get_session_id()) +
                                         ", Got: " + std::to_string(auth_gg_packet->getSessionId()));

                    // TODO: Send login fail packet (matches Rust behavior)
                    connection->force_disconnect();
                    break;
                }

                // Create and send AuthGG response
                auto auth_gg_response = PacketFactory::createAuthGGResponse(connection->get_session_id());
                connection->send_packet(std::move(auth_gg_response));

                log_connection_event("AuthGG validated and response sent to " + connection->get_remote_address());
            }
            else
            {
                log_connection_event("Failed to cast AuthGG packet from " + connection->get_remote_address());
            }
            break;
        }

        case 0x05: // RequestServerList
        {
            log_connection_event("Received server list request from " + connection->get_remote_address());
            connection->send_server_list();
            break;
        }

        case 0x02: // RequestGSLogin
        {
            log_connection_event("Received game server login from " + connection->get_remote_address());
            connection->send_play_ok();
            break;
        }

        default:
            log_connection_event("Received unknown packet ID 0x" +
                                 std::to_string(packet_id) + " from " + connection->get_remote_address());
            break;
        }
    }
    catch (const std::exception &e)
    {
        log_connection_event("Error handling packet from " + connection->get_remote_address() +
                             ": " + e.what());
        connection->force_disconnect();
    }
}

void ConnectionManager::handle_connection_state_change(ClientConnection *connection,
                                                       ClientConnection::State old_state,
                                                       ClientConnection::State new_state)
{
    if (config_.enable_connection_logging)
    {
        log_connection_event("Connection " + connection->get_remote_address() +
                             " state changed: " + state_to_string(old_state) +
                             " -> " + state_to_string(new_state));
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

std::string connection_state_to_string(ClientConnection::State state)
{
    return std::string(state_to_string(state));
}

std::string format_bytes(uint64_t bytes)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit < 4)
    {
        size /= 1024.0;
        unit++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

std::string format_duration(std::chrono::seconds duration)
{
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration % std::chrono::hours(1));
    auto seconds = duration % std::chrono::minutes(1);

    std::ostringstream oss;
    oss << hours.count() << "h " << minutes.count() << "m " << seconds.count() << "s";
    return oss.str();
}