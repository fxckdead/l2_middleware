#include <iostream>
#include <string>

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
#include "login_server.hpp"

// Forward declaration for packet integration tests
void run_all_packet_tests();

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
    bool run_async = false;

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
        else if (arg == "--async" || arg == "-a")
        {
            run_async = true;
        }
    }

    if (show_help)
    {
        std::cout << "\nUsage: " << argv[0] << " [options]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --skip-tests, -s    Skip cryptographic and packet tests" << std::endl;
        std::cout << "  --async, -a         Run server in background thread" << std::endl;
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

    try
    {
        // Configure the login server
        LoginServer::Config server_config;
        server_config.bind_address = "127.0.0.1";                     // Change to "0.0.0.0" for external connections
        server_config.port = 2106;                                    // Standard L2 login server port
        server_config.max_connections = 500;                          // Adjust based on your needs
        server_config.rsa_key_pool_size = 10;                         // Pool of RSA keys for load balancing
        server_config.enable_logging = true;                          // Connection and packet logging
        server_config.connection_timeout = std::chrono::seconds(300); // 5 minutes

        // Create and start the login server
        std::cout << "\n[Startup] Initializing L2 Login Server..." << std::endl;
        LoginServer login_server(server_config);

        if (run_async)
        {
            // Run server in background thread
            login_server.run_async();

            std::cout << "\nServer running in background. Press Enter to stop..." << std::endl;
            std::cin.get();

            login_server.stop();
            login_server.wait_for_shutdown();
        }
        else
        {
            // Run server in main thread (blocking)
            login_server.run();
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "\n[ERROR] Server failed to start: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
