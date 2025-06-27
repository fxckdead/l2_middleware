#include <iostream>
#include <string>

#include <boost/asio.hpp>

#include "rsa_manager.hpp"
#include "blowfish_openssl.hpp"

using boost::asio::ip::tcp;

void test_blowfish_openssl()
{
    std::cout << "=== Testing OpenSSL Blowfish ===" << std::endl;

    // Initialize Blowfish with a key
    std::string key = "MySecretKey123";
    Blowfish bf(key);

    // Test data
    uint32_t left = 0x12345678;
    uint32_t right = 0x90ABCDEF;

    // Make a copy for verification
    uint32_t orig_left = left;
    uint32_t orig_right = right;

    std::cout << "Original: 0x" << std::hex << orig_left << " 0x" << orig_right << std::endl;

    // Encrypt
    bf.encrypt(left, right);
    std::cout << "Encrypted: 0x" << std::hex << left << " 0x" << right << std::endl;

    // Decrypt
    bf.decrypt(left, right);
    std::cout << "Decrypted: 0x" << std::hex << left << " 0x" << right << std::dec << std::endl;

    // Verify
    if (left == orig_left && right == orig_right)
    {
        std::cout << "✅ OpenSSL Blowfish test PASSED!" << std::endl;
    }
    else
    {
        std::cout << "❌ OpenSSL Blowfish test FAILED!" << std::endl;
    }
    std::cout << std::endl;
}

void test_rsa_manager()
{
    // Run comprehensive RSA test suite
    RSAManager::runAllTests();
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

    std::cout << "\n"
              << std::string(50, '=') << std::endl;
    std::cout << "Starting TCP server..." << std::endl;
    start_tcp_server();

    return 0;
}
