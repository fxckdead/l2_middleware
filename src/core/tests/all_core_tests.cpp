#include <iostream>
#include <string>

// Include all test files
#include "encryption/blowfish_test.cpp"
#include "encryption/game_client_encryption_test.cpp"
#include "encryption/l2_checksum_test.cpp"
#include "encryption/login_encryption_test.cpp"
#include "encryption/rsa_manager_test.cpp"
#include "network/packet_buffer_test.cpp"
#include "packets/packet_test.cpp"
#include "utils/session_key_test.cpp"

void run_all_core_tests()
{
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "        L2 MIDDLEWARES - CORE MODULE TEST SUITE" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // Test cryptographic components
    test_blowfish_encryption();
    test_game_client_encryption();
    test_l2_checksum();
    test_login_encryption();
    test_rsa_manager_all();

    // Test network components
    test_readable_packet_buffer();
    test_sendable_packet_buffer();

    // Test packet components
    test_packet_utilities();

    // Test utility components
    test_session_key();

    std::cout << std::string(60, '=') << std::endl;
    std::cout << "        ALL CORE MODULE TESTS COMPLETED" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
} 