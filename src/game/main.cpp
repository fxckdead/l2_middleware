#include <iostream>
#include <string>

#include "server/game_server.hpp"

int main(int argc, char *argv[])
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "        L2 MIDDLEWARES - LINEAGE 2 GAME SERVER" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // Check for command line arguments
    bool show_help = false;
    bool run_async = false;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h")
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
        std::cout << "  --async, -a         Run server in background thread" << std::endl;
        std::cout << "  --help, -h          Show this help message" << std::endl;
        std::cout << "\nDefault behavior: Start game server on 127.0.0.1:7777" << std::endl;
        return 0;
    }

    try
    {
        // Configure the game server
        GameServer::Config server_config;
        server_config.bind_address = "127.0.0.1";                   // Change to "0.0.0.0" for external connections
        server_config.port = 7777;                                  // Standard L2 game server port
        server_config.max_connections = 1000;                       // Game servers typically handle more connections
        server_config.enable_logging = true;                        // Connection and packet logging
        server_config.connection_timeout = std::chrono::seconds(30); // 30 seconds for game connections

        // Create and start the game server
        std::cout << "\n[Startup] Initializing L2 Game Server..." << std::endl;
        GameServer game_server(server_config);

        if (run_async)
        {
            // Run server in background thread
            game_server.run_async();

            std::cout << "\nServer running in background. Press Enter to stop..." << std::endl;
            std::cin.get();

            game_server.stop();
            game_server.wait_for_shutdown();
        }
        else
        {
            // Run server in main thread (blocking)
            game_server.run();
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "\n[ERROR] Server failed to start: " << e.what() << std::endl;
        return 1;
    }

    return 0;
} 