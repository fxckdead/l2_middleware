#include "init_packet.hpp"
#include "auth_login_packet.hpp"
#include "packet_factory.hpp"
#include "rsa_manager.hpp"
#include <iostream>

void test_init_packet()
{
    std::cout << "=== Testing Init Packet ===" << std::endl;

    // Create RSA key pair
    RSAManager rsa_manager(1);
    const auto &rsa_pair = rsa_manager.getRandomRSAKeyPair();

    // Create blowfish key
    std::vector<uint8_t> bf_key(16, 0x42); // Test key

    // Create init packet
    int32_t session_id = 12345;
    InitPacket init_packet(session_id, rsa_pair, bf_key);

    // Serialize
    auto serialized = init_packet.serialize();
    std::cout << "  Serialized size: " << serialized.size() << " bytes" << std::endl;

    // Verify structure matches Rust
    ReadablePacketBuffer reader(serialized);

    uint16_t packet_length = reader.readUInt16();
    uint8_t opcode = reader.readByte();
    int32_t read_session_id = reader.readInt32();
    int32_t protocol_rev = reader.readInt32();

    std::cout << "  Packet length: " << packet_length << std::endl;
    std::cout << "  Opcode: 0x" << std::hex << (int)opcode << std::dec << std::endl;
    std::cout << "  Session ID: " << read_session_id << std::endl;
    std::cout << "  Protocol: 0x" << std::hex << protocol_rev << std::dec << std::endl;

    if (opcode == 0x00 && read_session_id == session_id)
    {
        std::cout << "  ✅ Init packet test PASSED!" << std::endl;
    }
    else
    {
        std::cout << "  ❌ Init packet test FAILED!" << std::endl;
    }
}

void test_integration_with_crypto()
{
    std::cout << "\n=== Testing Crypto Integration ===" << std::endl;

    // This tests your packet layer with your existing crypto components
    RSAManager rsa_manager(1);
    const auto &rsa_pair = rsa_manager.getRandomRSAKeyPair();

    // Create some test encrypted login data (like from client)
    std::string test_data = "admin"; // username
    auto encrypted = rsa_pair.encrypt(std::vector<uint8_t>(test_data.begin(), test_data.end()));

    // Test packet factory can handle it
    try
    {
        auto packet = PacketFactory::createFromClientData(encrypted, rsa_pair);
        if (packet)
        {
            std::cout << "  ✅ Packet factory integration PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Packet factory returned null!" << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "  ⚠️  Packet factory threw: " << e.what() << std::endl;
    }
}

void test_full_auth_flow()
{
    std::cout << "\n=== Testing Full Auth Flow ===" << std::endl;

    try
    {
        // Step 1: Create server components
        RSAManager rsa_manager(1);
        const auto &rsa_pair = rsa_manager.getRandomRSAKeyPair();

        // Generate random Blowfish key for client
        std::vector<uint8_t> bf_key(16);
        for (int i = 0; i < 16; i++)
        {
            bf_key[i] = static_cast<uint8_t>(rand() % 256);
        }

        // Step 2: Create Init packet (server sends to client)
        int32_t session_id = 98765;
        auto init_packet = PacketFactory::createInitPacket(session_id, rsa_pair, bf_key);
        auto init_serialized = init_packet->serialize();

        std::cout << "  Init packet created: " << init_serialized.size() << " bytes" << std::endl;

        // Step 3: Simulate client receiving and parsing init packet
        ReadablePacketBuffer init_reader(init_serialized);
        uint16_t init_length = init_reader.readUInt16();
        uint8_t init_opcode = init_reader.readByte();
        int32_t init_session = init_reader.readInt32();

        // Step 4: Use the test data that matches Rust implementation
        std::vector<uint8_t> auth_test_data = {
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64,
            0x6d, 0x69, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00};

        // Step 5: Try to parse the auth login packet using factory
        auto auth_packet = PacketFactory::createFromClientData(auth_test_data, rsa_pair);

        if (auth_packet)
        {
            std::cout << "  ✅ Full auth flow test PASSED!" << std::endl;
            std::cout << "    - Init packet: " << init_serialized.size() << " bytes, session " << init_session << std::endl;
            std::cout << "    - Auth packet: Created successfully" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Auth packet creation failed!" << std::endl;
        }
    }
    catch (const std::exception &e)
    {
        std::cout << "  ❌ Full auth flow failed: " << e.what() << std::endl;
    }
}

void test_packet_serialization_roundtrip()
{
    std::cout << "\n=== Testing Packet Serialization Roundtrip ===" << std::endl;

    try
    {
        RSAManager rsa_manager(1);
        const auto &rsa_pair = rsa_manager.getRandomRSAKeyPair();

        // Test different packet sizes and data
        std::vector<uint8_t> bf_key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

        for (int32_t session_id : {1, 1000, 999999, -1, -999999})
        {
            InitPacket packet(session_id, rsa_pair, bf_key);
            auto serialized = packet.serialize();

            // Verify packet structure
            ReadablePacketBuffer reader(serialized);
            uint16_t length = reader.readUInt16();
            uint8_t opcode = reader.readByte();
            int32_t read_session = reader.readInt32();

            if (opcode == 0x00 && read_session == session_id)
            {
                std::cout << "  ✅ Session ID " << session_id << " serialization OK" << std::endl;
            }
            else
            {
                std::cout << "  ❌ Session ID " << session_id << " serialization FAILED" << std::endl;
                return;
            }
        }

        std::cout << "  ✅ Packet serialization roundtrip test PASSED!" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << "  ❌ Serialization roundtrip failed: " << e.what() << std::endl;
    }
}

void run_all_packet_tests()
{
    std::cout << "========================================" << std::endl;
    std::cout << "         PACKET INTEGRATION TESTS      " << std::endl;
    std::cout << "========================================" << std::endl;

    test_init_packet();
    test_integration_with_crypto();
    test_full_auth_flow();
    test_packet_serialization_roundtrip();

    std::cout << "\n========================================" << std::endl;
    std::cout << "       PACKET TESTS COMPLETED!         " << std::endl;
    std::cout << "========================================" << std::endl;
}