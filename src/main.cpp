#include <iostream>
#include <string>

#include <boost/asio.hpp>

#include "rsa_manager.hpp"
#include "blowfish_openssl.hpp"
#include "l2_checksum.hpp"
#include "login_encryption.hpp"
#include "session_key.hpp"

using boost::asio::ip::tcp;

void test_blowfish_openssl()
{
    Blowfish::runTests();
}

void test_rsa_manager()
{
    // Run comprehensive RSA test suite
    RSAManager::runAllTests();
}

void test_l2_checksum()
{
    L2Checksum::runTests();
}

void test_login_encryption()
{
    LoginEncryption::runTests();
}

void test_session_key()
{
    SessionKey::runTests();
}

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

int main()
{
    // Test OpenSSL Blowfish functionality
    test_blowfish_openssl();

    // Test RSA manager functionality
    test_rsa_manager();

    // Test L2 checksum functionality
    test_l2_checksum();

    // Test Login encryption functionality (Rust compatibility)
    test_login_encryption();

    // Test Session Key management (Rust compatibility)
    test_session_key();

    std::cout << "\n"
              << std::string(50, '=') << std::endl;
    std::cout << "Starting TCP server..." << std::endl;
    start_tcp_server();

    return 0;
}
