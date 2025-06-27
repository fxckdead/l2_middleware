#include <iostream>
#include <string>
#include <iomanip>
#include <vector>

#include <boost/asio.hpp>

#include "rsa_manager.hpp"
#include "blowfish_openssl.hpp"

using boost::asio::ip::tcp;

void test_blowfish_openssl()
{
    std::cout << "=== Testing OpenSSL Blowfish ===" << std::endl;

    // Test 1: Original uint32_t interface
    std::cout << "Test 1: uint32_t interface" << std::endl;

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
    bool test1_passed = (left == orig_left && right == orig_right);
    if (test1_passed)
    {
        std::cout << "✅ Test 1 PASSED!" << std::endl;
    }
    else
    {
        std::cout << "❌ Test 1 FAILED!" << std::endl;
    }

    // Test 2: Little Endian byte array interface (Rust BlowfishLE compatibility)
    std::cout << "\nTest 2: Little Endian byte array interface (Rust compatibility)" << std::endl;

    // Test data: 16 bytes (2 blocks of 8 bytes each)
    std::vector<uint8_t> test_data = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Block 1
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18  // Block 2
    };

    // Make a copy for verification
    std::vector<uint8_t> original_data = test_data;

    std::cout << "Original data: ";
    for (uint8_t byte : original_data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    // Encrypt using Little Endian interface
    bf.encrypt_bytes(test_data);

    std::cout << "Encrypted data: ";
    for (uint8_t byte : test_data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    // Decrypt using Little Endian interface
    bf.decrypt_bytes(test_data);

    std::cout << "Decrypted data: ";
    for (uint8_t byte : test_data)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;

    // Verify
    bool test2_passed = (test_data == original_data);
    if (test2_passed)
    {
        std::cout << "✅ Test 2 PASSED!" << std::endl;
    }
    else
    {
        std::cout << "❌ Test 2 FAILED!" << std::endl;
    }

    // Overall result
    if (test1_passed && test2_passed)
    {
        std::cout << "🎉 ALL Blowfish tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "⚠️ Some Blowfish tests FAILED!" << std::endl;
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
