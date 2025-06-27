#pragma once

#include "packet.hpp"
#include "packet_buffer.hpp"
#include "rsa_manager.hpp"
#include <vector>
#include <cstdint>

// InitPacket - First packet sent to connecting clients
// Matches the network flow described in network-steps.md
// Structure: Opcode + Session ID + Protocol + RSA Key + GameGuard + Blowfish Key + Null
class InitPacket : public SendablePacket
{
private:
    static constexpr uint8_t OPCODE = 0x00;
    static constexpr int32_t PROTOCOL_REVISION = 0x0000c621; // From L2 protocol

    int32_t m_sessionId;
    std::vector<uint8_t> m_scrambledModulus; // 128 bytes (scrambled RSA modulus)
    std::vector<uint8_t> m_gameGuardData;    // 16 bytes of GameGuard constants
    std::vector<uint8_t> m_blowfishKey;      // 16 bytes (random Blowfish key)

public:
    // Constructor
    InitPacket(int32_t sessionId,
               const ScrambledRSAKeyPair &rsaPair,
               const std::vector<uint8_t> &blowfishKey);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;

    // Accessors
    int32_t getSessionId() const { return m_sessionId; }
    const std::vector<uint8_t> &getBlowfishKey() const { return m_blowfishKey; }
    const std::vector<uint8_t> &getScrambledModulus() const { return m_scrambledModulus; }
    const std::vector<uint8_t> &getGameGuardData() const { return m_gameGuardData; }

    // Factory method for creating with default GameGuard data
    static InitPacket create(int32_t sessionId,
                             const ScrambledRSAKeyPair &rsaPair,
                             const std::vector<uint8_t> &blowfishKey);

    // Test function
    static void runTests();

private:
    // Generate default GameGuard authentication data (16 bytes of constants)
    static std::vector<uint8_t> generateDefaultGameGuardData();

    // Validate packet data
    bool isValid() const;
};