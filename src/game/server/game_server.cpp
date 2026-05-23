#include "game_server.hpp"
#include "../network/game_connection_manager.hpp"
#include "../network/game_client_connection.hpp"
#include "character_database_manager.hpp"
#include <iostream>
#include <iomanip>
#include <thread>
#include <csignal>
#include <ctime>

using boost::asio::ip::tcp;

// Global instance for signal handling
GameServer *g_game_server_instance = nullptr;

// Signal handler function
void handle_signal(int signal_number)
{
    if (g_game_server_instance)
    {
        g_game_server_instance->handle_signal(signal_number);
    }
}

// =============================================================================
// Constructor and Destructor
// =============================================================================

GameServer::GameServer(const Config &config)
    : config_(config)
{
    g_game_server_instance = this;
    initialize_server();
}

GameServer::~GameServer()
{
    if (running_.load())
    {
        stop();
    }
    g_game_server_instance = nullptr;
}

// =============================================================================
// Server Lifecycle
// =============================================================================

void GameServer::start()
{
    if (running_.load())
    {
        return;
    }

    print_startup_banner();

    try
    {
        // Create acceptor
        tcp::endpoint endpoint(tcp::v4(), config_.port);

        acceptor_ = std::make_unique<tcp::acceptor>(io_context_, endpoint);

        // Setup signal handlers
        setup_signal_handlers();

        running_.store(true);
        log_server_event("Server started on " + config_.bind_address + ":" + std::to_string(config_.port));

        // Start accepting connections
        start_accepting();
        // Start world tick after accepting begins.
        start_world_tick();
    }
    catch (const std::exception &e)
    {
        log_server_event("Failed to start server: " + std::string(e.what()));
        throw;
    }
}

void GameServer::stop()
{
    if (!running_.load())
    {
        return;
    }

    shutdown_requested_.store(true);
    log_server_event("Stop requested");

    shutdown_server();
}

void GameServer::run()
{
    start();

    try
    {
        // Run the IO context (blocking)
        io_context_.run();
    }
    catch (const std::exception &e)
    {
        log_server_event("Server error: " + std::string(e.what()));
    }

    print_shutdown_message();
}

void GameServer::run_async()
{
    start();

    // Run server in background thread
    server_thread_ = std::make_unique<std::thread>([this]()
                                                   {
        try 
        {
            io_context_.run();
        }
        catch (const std::exception& e) 
        {
            log_server_event("Background server error: " + std::string(e.what()));
        } });
}

void GameServer::wait_for_shutdown()
{
    if (server_thread_ && server_thread_->joinable())
    {
        server_thread_->join();
        server_thread_.reset();
    }
}

// =============================================================================
// Status and Statistics
// =============================================================================

size_t GameServer::get_active_connections() const
{
    return connection_manager_ ? connection_manager_->get_connection_count() : 0;
}

void GameServer::print_statistics() const
{
    if (connection_manager_)
    {
        connection_manager_->print_stats();
    }
}

void GameServer::set_config(const Config &config)
{
    config_ = config;
}

// =============================================================================
// Signal Handling
// =============================================================================

void GameServer::handle_signal(int signal_number)
{
    log_server_event("Received signal " + std::to_string(signal_number));

    switch (signal_number)
    {
    case SIGINT:
    case SIGTERM:
        log_server_event("Shutdown signal received");
        stop();
        break;
    default:
        log_server_event("Unhandled signal: " + std::to_string(signal_number));
        break;
    }
}

// =============================================================================
// Private Implementation
// =============================================================================

void GameServer::initialize_server()
{
    log_server_event("Initializing game server");

    // Initialize character database manager first (critical service)
    character_database_manager_ = std::make_unique<CharacterDatabaseManager>();
    if (!character_database_manager_) {
        throw std::runtime_error("Failed to initialize character database manager");
    }
    log_server_event("Character database manager initialized");

    // Create game-specific connection manager
    BaseConnectionManager::Config conn_config;
    conn_config.max_connections = config_.max_connections;
    conn_config.enable_connection_logging = config_.enable_logging;
    conn_config.connection_timeout = config_.connection_timeout;

    connection_manager_ = std::make_unique<GameConnectionManager>(io_context_, conn_config);

    log_server_event("Server initialized");
}

void GameServer::start_accepting()
{
    if (!acceptor_)
    {
        return;
    }

    // TODO: Implement connection handling when GameConnectionManager is ready
    // For now, we'll just accept connections but not handle them
    auto new_socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);

    acceptor_->async_accept(*new_socket,
                            [this, new_socket](boost::system::error_code ec)
                            {
                                handle_accept(ec, std::move(*new_socket));
                            });
}

void GameServer::handle_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
{
    if (!running_.load())
    {
        return;
    }

    if (!ec)
    {
        // Create new connection using the game connection manager
        auto connection = connection_manager_->create_connection(std::move(socket));

        if (connection)
        {
            // Add to connection manager (this will initialize and start the connection)
            if (connection_manager_->add_connection(connection))
            {
                // Start the connection
                connection->start();
            }
        }
    }
    else
    {
        log_server_event("Accept error: " + ec.message());
    }

    // Continue accepting new connections
    if (running_.load())
    {
        start_accepting();
    }
}

void GameServer::setup_signal_handlers()
{
    signals_ = std::make_unique<boost::asio::signal_set>(io_context_, SIGINT, SIGTERM);

    signals_->async_wait([this](boost::system::error_code, int signal_number)
                         { handle_signal(signal_number); });
}

void GameServer::shutdown_server()
{
    running_.store(false);

    // Cancel world tick first so it stops re-arming.
    if (world_tick_timer_) {
        try {
            world_tick_timer_->cancel();
        } catch (const std::exception &) {
            // Ignore cancel errors during shutdown.
        }
    }

    // Close acceptor
    if (acceptor_)
    {
        boost::system::error_code ec;
        acceptor_->close(ec);
        acceptor_.reset();
    }

    // Disconnect all connections
    if (connection_manager_)
    {
        connection_manager_->disconnect_all();
    }

    // Stop IO context
    io_context_.stop();

    log_server_event("Server shutdown completed");
}

void GameServer::log_server_event(const std::string &event) const
{
    if (config_.enable_logging)
    {
        std::cout << "[GameServer] " << event << std::endl;
    }
}

void GameServer::print_startup_banner() const
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "        L2 MIDDLEWARES - GAME SERVER" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "Binding to: " << config_.bind_address << ":" << config_.port << std::endl;
    std::cout << "Max connections: " << config_.max_connections << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

void GameServer::print_shutdown_message() const
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "        GAME SERVER SHUTDOWN COMPLETE" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

void GameServer::start_world_tick()
{
    world_tick_timer_ = std::make_unique<boost::asio::steady_timer>(io_context_);
    world_tick_timer_->expires_after(kWorldTickInterval);
    world_tick_timer_->async_wait(
        [this](const boost::system::error_code &ec) { process_world_tick(ec); });
    log_server_event("World tick started ("
        + std::to_string(kWorldTickInterval.count()) + "ms interval)");
}

void GameServer::process_world_tick(const boost::system::error_code &ec)
{
    if (ec == boost::asio::error::operation_aborted) {
        return; // cancellation - normal during shutdown
    }
    if (ec) {
        log_server_event("World tick error: " + ec.message());
        return;
    }

    const int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    if (connection_manager_) {
        auto conns = connection_manager_->get_all_connections();
        for (auto &base : conns) {
            try {
                auto game_conn = std::dynamic_pointer_cast<GameClientConnection>(base);
                if (game_conn) {
                    game_conn->advance_player_movement(nowMs);
                }
            } catch (const std::exception &e) {
                log_server_event(std::string("World tick: per-connection exception: ") + e.what());
            }
        }
    }

    // Re-arm.
    if (running_.load() && world_tick_timer_) {
        world_tick_timer_->expires_after(kWorldTickInterval);
        world_tick_timer_->async_wait(
            [this](const boost::system::error_code &ec) { process_world_tick(ec); });
    }
}
