#include <iostream>
#include <string>
#include <csignal>
#include <memory>

#include <boost/asio.hpp>

#include "rsa_manager.hpp"
#include "blowfish_openssl.hpp"
#include "l2_checksum.hpp"
#include "login_encryption.hpp"
#include "session_key.hpp"
#include "game_client_encryption.hpp"
#include "packet.hpp"
#include "packet_buffer.hpp"
#include "init_packet.hpp"
#include "auth_login_packet.hpp"
#include "packet_factory.hpp"
#include "connection_manager.hpp"
#include "client_connection.hpp"

// Forward declaration for packet integration tests
void run_all_packet_tests();

using boost::asio::ip::tcp;

// Global server state for signal handling
std::unique_ptr<ConnectionManager> g_connection_manager;
boost::asio::io_context *g_io_context = nullptr;
std::unique_ptr<tcp::acceptor> g_acceptor;

// Server configuration
struct ServerConfig
{
    std::string bind_address = "127.0.0.1";
    uint16_t port = 2106;
    uint32_t max_connections = 1000;
    uint32_t rsa_key_pool_size = 10;
    bool enable_logging = true;
};

// Signal handler for graceful shutdown
void signal_handler(int signal)
{
    std::cout << "\n[Server] Received signal " << signal << ", shutting down gracefully..." << std::endl;

    if (g_acceptor)
    {
        boost::system::error_code ec;
        g_acceptor->close(ec);
    }

    if (g_connection_manager)
    {
        g_connection_manager->disconnect_all();
        g_connection_manager->print_stats();
    }

    if (g_io_context)
    {
        g_io_context->stop();
    }
}

// Async accept handler
void handle_accept(boost::system::error_code ec, tcp::socket socket)
{
    if (!g_acceptor->is_open())
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

        std::cout << "[Server] New connection from: " << client_address << std::endl;

        // Create and start new connection
        auto connection = g_connection_manager->create_connection(std::move(socket));
        if (connection)
        {
            if (g_connection_manager->add_connection(connection))
            {
                connection->start();
                std::cout << "[Server] Connection established and initialized" << std::endl;
            }
            else
            {
                std::cout << "[Server] Failed to add connection (limit reached?)" << std::endl;
            }
        }
        else
        {
            std::cout << "[Server] Failed to create connection" << std::endl;
        }
    }
    else
    {
        std::cout << "[Server] Accept error: " << ec.message() << std::endl;
    }

    // Continue accepting new connections
    if (g_acceptor->is_open())
    {
        g_acceptor->async_accept([](boost::system::error_code ec, tcp::socket socket)
                                 { handle_accept(ec, std::move(socket)); });
    }
}

void start_l2_login_server(const ServerConfig &config)
{
    try
    {
        boost::asio::io_context io_context;
        g_io_context = &io_context;

        // Create connection manager
        ConnectionManager::Config mgr_config;
        mgr_config.max_connections = config.max_connections;
        mgr_config.rsa_key_pool_size = config.rsa_key_pool_size;
        mgr_config.enable_connection_logging = config.enable_logging;

        g_connection_manager = std::make_unique<ConnectionManager>(io_context, mgr_config);

        // Create TCP acceptor
        tcp::endpoint endpoint(boost::asio::ip::make_address(config.bind_address), config.port);
        g_acceptor = std::make_unique<tcp::acceptor>(io_context, endpoint);

        std::cout << "\n"
                  << std::string(60, '=') << std::endl;
        std::cout << "        L2 MIDDLEWARES - LOGIN SERVER STARTED" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        std::cout << "Listening on: " << config.bind_address << ":" << config.port << std::endl;
        std::cout << "Max connections: " << config.max_connections << std::endl;
        std::cout << "RSA key pool: " << config.rsa_key_pool_size << " keys" << std::endl;
        std::cout << "Ready for Lineage 2 client connections!" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        // Set up signal handlers
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Start accepting connections
        g_acceptor->async_accept([](boost::system::error_code ec, tcp::socket socket)
                                 { handle_accept(ec, std::move(socket)); });

        // Run the server
        std::cout << "[Server] Starting I/O event loop..." << std::endl;
        io_context.run();

        std::cout << "[Server] I/O event loop stopped" << std::endl;
    }
    catch (std::exception &e)
    {
        std::cerr << "[Server] Fatal error: " << e.what() << std::endl;
    }

    // Cleanup
    g_acceptor.reset();
    g_connection_manager.reset();
    g_io_context = nullptr;
}

void run_all_tests()
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "        L2 MIDDLEWARES - CRYPTOGRAPHIC TEST SUITE" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // Test cryptographic components
    Blowfish::runTests();
    GameClientEncryption::runTests();
    L2Checksum::runTests();
    LoginEncryption::runTests();
    SessionKey::runTests();
    RSAManager::runAllTests();

    // Test packet layer components
    PacketUtils::runTests();
    ReadablePacketBuffer::runTests();
    SendablePacketBuffer::runTests();
    InitPacket::runTests();
    AuthLoginPacket::runTests();
    PacketFactory::runTests();

    // Demo L2 authentication flow
    AuthLoginPacket::demoL2AuthFlow();

    // Run packet integration tests
    run_all_packet_tests();

    std::cout << std::string(60, '=') << std::endl;
    std::cout << "        ALL COMPONENT TESTS COMPLETED" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

int main(int argc, char *argv[])
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "        L2 MIDDLEWARES - LINEAGE 2 LOGIN SERVER" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "Build: C++ Implementation with OpenSSL Crypto" << std::endl;
    std::cout << "Compatible with: Lineage 2 Classic/Interlude/High Five" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // Check for command line arguments
    bool skip_tests = false;
    bool show_help = false;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--skip-tests" || arg == "-s")
        {
            skip_tests = true;
        }
        else if (arg == "--help" || arg == "-h")
        {
            show_help = true;
        }
    }

    if (show_help)
    {
        std::cout << "\nUsage: " << argv[0] << " [options]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --skip-tests, -s    Skip cryptographic and packet tests" << std::endl;
        std::cout << "  --help, -h          Show this help message" << std::endl;
        std::cout << "\nDefault behavior: Run tests, then start login server on 127.0.0.1:2106" << std::endl;
        return 0;
    }

    // Run comprehensive tests first (unless skipped)
    if (!skip_tests)
    {
        std::cout << "\n[Startup] Running cryptographic and packet validation tests..." << std::endl;
        run_all_tests();
        std::cout << "[Startup] All tests completed successfully!" << std::endl;
    }
    else
    {
        std::cout << "\n[Startup] Skipping tests as requested" << std::endl;
    }

    // Server configuration
    ServerConfig server_config;

    // You can modify these settings or load from a config file
    server_config.bind_address = "127.0.0.1"; // Change to "0.0.0.0" for external connections
    server_config.port = 2106;                // Standard L2 login server port
    server_config.max_connections = 500;      // Adjust based on your needs
    server_config.rsa_key_pool_size = 10;     // Pool of RSA keys for load balancing
    server_config.enable_logging = true;      // Connection and packet logging

    // Start the L2 login server
    std::cout << "\n[Startup] Initializing L2 Login Server..." << std::endl;
    start_l2_login_server(server_config);

    std::cout << "\n[Shutdown] L2 Login Server has stopped" << std::endl;
    std::cout << "Thank you for using L2 Middlewares!" << std::endl;

    return 0;
}
