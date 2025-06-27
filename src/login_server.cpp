#include "login_server.hpp"
#include <iostream>
#include <iomanip>

using boost::asio::ip::tcp;

// Global instance for signal handling
LoginServer *g_login_server_instance = nullptr;

// C-style signal handler that delegates to the server instance
extern "C" void global_signal_handler(int signal_number)
{
    if (g_login_server_instance)
    {
        g_login_server_instance->handle_signal(signal_number);
    }
}

// =============================================================================
// Constructor and Destructor
// =============================================================================

LoginServer::LoginServer(const Config &config)
    : config_(config)
{
    // Set global instance for signal handling
    g_login_server_instance = this;

    log_server_event("LoginServer created with configuration:");
    log_server_event("  Address: " + config_.bind_address + ":" + std::to_string(config_.port));
    log_server_event("  Max connections: " + std::to_string(config_.max_connections));
    log_server_event("  RSA key pool: " + std::to_string(config_.rsa_key_pool_size));
}

LoginServer::~LoginServer()
{
    stop();

    // Clear global instance
    if (g_login_server_instance == this)
    {
        g_login_server_instance = nullptr;
    }

    log_server_event("LoginServer destroyed");
}

// =============================================================================
// Server Lifecycle
// =============================================================================

void LoginServer::start()
{
    if (running_.load())
    {
        log_server_event("Server is already running");
        return;
    }

    try
    {
        initialize_server();
        setup_signal_handlers();
        start_accepting();

        running_.store(true);
        print_startup_banner();

        log_server_event("L2 Login Server started successfully");
    }
    catch (const std::exception &e)
    {
        log_server_event("Failed to start server: " + std::string(e.what()));
        throw;
    }
}

void LoginServer::stop()
{
    if (!running_.load())
    {
        return;
    }

    log_server_event("Initiating server shutdown...");
    shutdown_requested_.store(true);
    shutdown_server();
}

void LoginServer::run()
{
    if (!running_.load())
    {
        start();
    }

    try
    {
        log_server_event("Starting I/O event loop (blocking)...");
        io_context_.run();
        log_server_event("I/O event loop stopped");
    }
    catch (const std::exception &e)
    {
        log_server_event("I/O context error: " + std::string(e.what()));
        throw;
    }

    print_shutdown_message();
}

void LoginServer::run_async()
{
    if (server_thread_ && server_thread_->joinable())
    {
        log_server_event("Server thread is already running");
        return;
    }

    server_thread_ = std::make_unique<std::thread>([this]()
                                                   { run(); });

    log_server_event("Server started in background thread");
}

void LoginServer::wait_for_shutdown()
{
    if (server_thread_ && server_thread_->joinable())
    {
        server_thread_->join();
        server_thread_.reset();
        log_server_event("Server thread joined");
    }
}

// =============================================================================
// Status and Statistics
// =============================================================================

size_t LoginServer::get_active_connections() const
{
    return connection_manager_ ? connection_manager_->get_connection_count() : 0;
}

void LoginServer::print_statistics() const
{
    if (connection_manager_)
    {
        connection_manager_->print_stats();
    }
    else
    {
        std::cout << "Connection manager not initialized" << std::endl;
    }
}

void LoginServer::set_config(const Config &config)
{
    if (running_.load())
    {
        log_server_event("Cannot change configuration while server is running");
        return;
    }

    config_ = config;
    log_server_event("Server configuration updated");
}

// =============================================================================
// Server Implementation
// =============================================================================

void LoginServer::initialize_server()
{
    // Create ConnectionManager with our configuration
    ConnectionManager::Config mgr_config;
    mgr_config.max_connections = config_.max_connections;
    mgr_config.rsa_key_pool_size = config_.rsa_key_pool_size;
    mgr_config.enable_connection_logging = config_.enable_logging;
    mgr_config.connection_timeout = config_.connection_timeout;

    connection_manager_ = std::make_unique<ConnectionManager>(io_context_, mgr_config);

    // Create TCP acceptor
    tcp::endpoint endpoint(boost::asio::ip::make_address(config_.bind_address), config_.port);
    acceptor_ = std::make_unique<tcp::acceptor>(io_context_, endpoint);

    // Configure acceptor options
    acceptor_->set_option(tcp::acceptor::reuse_address(true));

    log_server_event("Server components initialized");
}

void LoginServer::start_accepting()
{
    if (!acceptor_ || !acceptor_->is_open())
    {
        throw std::runtime_error("Acceptor not initialized or closed");
    }

    acceptor_->async_accept(
        [this](boost::system::error_code ec, tcp::socket socket)
        {
            handle_accept(ec, std::move(socket));
        });
}

void LoginServer::handle_accept(boost::system::error_code ec, tcp::socket socket)
{
    if (shutdown_requested_.load())
    {
        return; // Server is shutting down
    }

    if (!ec)
    {
        // Get client endpoint for logging
        std::string client_address = "unknown";
        try
        {
            auto endpoint = socket.remote_endpoint();
            client_address = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
        }
        catch (const std::exception &)
        {
            // Ignore endpoint errors
        }

        log_server_event("New connection from: " + client_address);

        // Create and start new connection through ConnectionManager
        auto connection = connection_manager_->create_connection(std::move(socket));
        if (connection)
        {
            if (connection_manager_->add_connection(connection))
            {
                connection->start();
                log_server_event("Connection established and initialized");
            }
            else
            {
                log_server_event("Failed to add connection (limit reached?)");
            }
        }
        else
        {
            log_server_event("Failed to create connection");
        }
    }
    else if (ec != boost::asio::error::operation_aborted)
    {
        log_server_event("Accept error: " + ec.message());
    }

    // Continue accepting new connections if not shutting down
    if (!shutdown_requested_.load() && acceptor_ && acceptor_->is_open())
    {
        start_accepting();
    }
}

void LoginServer::setup_signal_handlers()
{
    signals_ = std::make_unique<boost::asio::signal_set>(io_context_, SIGINT, SIGTERM);

    signals_->async_wait(
        [this](boost::system::error_code ec, int signal_number)
        {
            if (!ec)
            {
                handle_signal(signal_number);
            }
        });

    // Also set up traditional C signal handlers as backup
    std::signal(SIGINT, global_signal_handler);
    std::signal(SIGTERM, global_signal_handler);
}

void LoginServer::handle_signal(int signal_number)
{
    log_server_event("Received signal " + std::to_string(signal_number) + " - initiating graceful shutdown");
    stop();
}

void LoginServer::shutdown_server()
{
    running_.store(false);

    // Close acceptor to stop accepting new connections
    if (acceptor_ && acceptor_->is_open())
    {
        boost::system::error_code ec;
        acceptor_->close(ec);
        log_server_event("Acceptor closed");
    }

    // Disconnect all clients and print statistics
    if (connection_manager_)
    {
        connection_manager_->disconnect_all();
        log_server_event("All connections disconnected");

        if (config_.enable_logging)
        {
            connection_manager_->print_stats();
        }
    }

    // Stop the I/O context
    if (!io_context_.stopped())
    {
        io_context_.stop();
        log_server_event("I/O context stopped");
    }
}

// =============================================================================
// Utility Methods
// =============================================================================

void LoginServer::log_server_event(const std::string &event) const
{
    if (config_.enable_logging)
    {
        std::cout << "[LoginServer] " << event << std::endl;
    }
}

void LoginServer::print_startup_banner() const
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "        L2 MIDDLEWARES - LOGIN SERVER STARTED" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "Listening on: " << config_.bind_address << ":" << config_.port << std::endl;
    std::cout << "Max connections: " << config_.max_connections << std::endl;
    std::cout << "RSA key pool: " << config_.rsa_key_pool_size << " keys" << std::endl;
    std::cout << "Connection timeout: " << config_.connection_timeout.count() << " seconds" << std::endl;
    std::cout << "Ready for Lineage 2 client connections!" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

void LoginServer::print_shutdown_message() const
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "        L2 MIDDLEWARES - SERVER SHUTDOWN COMPLETE" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "Thank you for using L2 Middlewares!" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}