#include "init_packet.hpp"
#include <random>
#include <iostream>
#include <iomanip>

// Constructor
InitPacket::InitPacket(int32_t sessionId,
                       const ScrambledRSAKeyPair &rsaPair,
                       const std::vector<uint8_t> &blowfishKey)
    : m_sessionId(sessionId), m_scrambledModulus(rsaPair.getScrambledModulus()), m_gameGuardData(generateDefaultGameGuardData()), m_blowfishKey(blowfishKey)
{
    if (!isValid())
    {
        throw PacketException("Invalid InitPacket parameters");
    }
}

// SendablePacket interface implementation
uint8_t InitPacket::getPacketId() const
{
    return OPCODE;
}

std::optional<uint16_t> InitPacket::getExPacketId() const
{
    return std::nullopt; // Init packet doesn't have extended packet ID
}

void InitPacket::write(SendablePacketBuffer &buffer)
{
    // Write packet structure according to network-steps.md:
    // Opcode + Session ID + Protocol + RSA Key + GameGuard + Blowfish Key + Null

    buffer.writeUInt8(OPCODE);             // Opcode: 0x00 (Init)
    buffer.writeInt32(m_sessionId);        // Session ID: random i32
    buffer.writeInt32(PROTOCOL_REVISION);  // Protocol revision: 0x0000c621
    buffer.writeBytes(m_scrambledModulus); // RSA public key: 128 bytes (scrambled modulus)
    buffer.writeBytes(m_gameGuardData);    // GameGuard data: 16 bytes of constants
    buffer.writeBytes(m_blowfishKey);      // Blowfish key: 16 bytes (random generated)
    buffer.writeUInt8(0x00);               // Null terminator: 1 byte
}

size_t InitPacket::getSize() const
{
    // Calculate total packet size:
    // 1 (opcode) + 4 (session_id) + 4 (protocol) + 128 (rsa) + 16 (gg) + 16 (bf) + 1 (null) = 170 bytes
    return 1 + 4 + 4 + m_scrambledModulus.size() + m_gameGuardData.size() + m_blowfishKey.size() + 1;
}

// Factory method
InitPacket InitPacket::create(int32_t sessionId,
                              const ScrambledRSAKeyPair &rsaPair,
                              const std::vector<uint8_t> &blowfishKey)
{
    return InitPacket(sessionId, rsaPair, blowfishKey);
}

// Generate default GameGuard authentication data (16 bytes of constants)
std::vector<uint8_t> InitPacket::generateDefaultGameGuardData()
{
    // GameGuard magical constants (REQUIRED by L2 client!)
    // These exact values match the working Rust implementation
    return std::vector<uint8_t>{
        // 0x29DD954E (little-endian)
        0x4E, 0x95, 0xDD, 0x29,
        // 0x77C39CFC (little-endian)
        0xFC, 0x9C, 0xC3, 0x77,
        // 0x97ADB620 (little-endian)
        0x20, 0xB6, 0xAD, 0x97,
        // 0x07BDE0F7 (little-endian)
        0xF7, 0xE0, 0xBD, 0x07};
}

// Validate packet data
bool InitPacket::isValid() const
{
    return m_scrambledModulus.size() == 128 && // Scrambled modulus should be 128 bytes
           m_gameGuardData.size() == 16 &&     // GameGuard data should be 16 bytes
           m_blowfishKey.size() == 16;         // Blowfish key should be 16 bytes
}
