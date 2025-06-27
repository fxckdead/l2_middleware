#include <iostream>
#include <string>

#include <boost/asio.hpp>

#include "rsa_manager.hpp"
#include "blowfish_openssl.hpp"
#include "l2_checksum.hpp"
#include "login_encryption.hpp"
#include "session_key.hpp"
#include "game_client_encryption.hpp"
#include "packet.hpp"
#include "packet_buffer.hpp"

using boost::asio::ip::tcp;

void start_tcp_server()
{
    try
    {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 2106));

        std::cout << "TCP server started on port 2106" << std::endl;

        while (true)
        {
            tcp::socket socket(io_context);
            acceptor.accept(socket);

            std::cout << "Client connected from: " << socket.remote_endpoint() << std::endl;

            // Keep connection open until client disconnects
            try
            {
                char data[1024];
                boost::system::error_code error;

                while (true)
                {
                    size_t length = socket.read_some(boost::asio::buffer(data), error);
                    if (error == boost::asio::error::eof)
                        break; // Connection closed cleanly by peer
                    else if (error)
                        throw boost::system::system_error(error);
                }
            }
            catch (std::exception &e)
            {
                std::cout << "Connection error: " << e.what() << std::endl;
            }

            std::cout << "Client disconnected" << std::endl;
        }
    }
    catch (std::exception &e)
    {
        std::cerr << "Server error: " << e.what() << std::endl;
    }
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

    std::cout << std::string(60, '=') << std::endl;
    std::cout << "        ALL COMPONENT TESTS COMPLETED" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

int main()
{
    // Run comprehensive tests first
    run_all_tests();

    std::cout << "\n"
              << std::string(50, '=') << std::endl;
    std::cout << "Starting TCP server..." << std::endl;
    start_tcp_server();

    return 0;
}
