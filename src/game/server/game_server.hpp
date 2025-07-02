#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <atomic>
#include <thread>
#include <csignal>
#include <chrono>

// Forward declarations
class GameConnectionManager;
class CharacterDatabaseManager;

class GameServer
{
public:
    // Server configuration
    struct Config
    {
        std::string bind_address;
        uint16_t port;
        uint32_t max_connections;
        bool enable_logging;
        std::chrono::seconds connection_timeout;

        // Default constructor
        Config()
            : bind_address("127.0.0.1"), port(7777), max_connections(1000), enable_logging(true), connection_timeout(30)
        {
        }
    };

private:
    // Core components
    boost::asio::io_context io_context_;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor_;
    std::unique_ptr<GameConnectionManager> connection_manager_;
    std::unique_ptr<CharacterDatabaseManager> character_database_manager_;

    // Server state
    Config config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_requested_{false};

    // Threading
    std::unique_ptr<std::thread> server_thread_;

    // Signal handling
    std::unique_ptr<boost::asio::signal_set> signals_;

public:
    explicit GameServer(const Config &config = Config{});
    ~GameServer();

    // Prevent copying
    GameServer(const GameServer &) = delete;
    GameServer &operator=(const GameServer &) = delete;

    // Server lifecycle
    void start();
    void stop();
    void run();               // Blocking call to run server
    void run_async();         // Non-blocking call (runs in background thread)
    void wait_for_shutdown(); // Wait for server to stop

    // Status and statistics
    bool is_running() const { return running_.load(); }
    size_t get_active_connections() const;
    void print_statistics() const;

    // Configuration
    const Config &get_config() const { return config_; }
    void set_config(const Config &config);

    // Character database management
    CharacterDatabaseManager* get_character_database_manager() const { return character_database_manager_.get(); }

    // Signal handling (needs to be public for global signal handler)
    void handle_signal(int signal_number);

private:
    // Server implementation
    void initialize_server();
    void start_accepting();
    void handle_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);
    void setup_signal_handlers();
    void shutdown_server();

    // Utility
    void log_server_event(const std::string &event) const;
    void print_startup_banner() const;
    void print_shutdown_message() const;
};

// Global instance for signal handling (needed for C signal handlers)
extern GameServer *g_game_server_instance; 