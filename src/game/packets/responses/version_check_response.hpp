#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>

// VersionCheck - Response to client's SendProtocolVersion packet
// Server opcode 0x00 in Interlude Update 3 protocol
// Must include dynamic encryption key and opcode obfuscation key per protocol
class VersionCheckResponse : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x00;
    static constexpr int32_t SUPPORTED_PROTOCOL_VERSION = 746; // Interlude Update 3
    
    bool protocol_ok_;
    std::vector<uint8_t> dynamic_key_;      // 16-byte Blowfish key
    uint32_t opcode_obfuscation_key_;       // Opcode obfuscation key (usually 0)
    uint32_t feature_flags_ = 0x00000300;   // Bitmask flags (GG/protocol options)
    uint8_t  reserved_ = 0x00;              // Reserved byte required by client

public:
    // Constructor
    explicit VersionCheckResponse(bool protocol_ok = true);
    VersionCheckResponse(bool protocol_ok, const std::vector<uint8_t>& dynamic_key, uint32_t obfuscation_key);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;

    // Accessors
    const std::vector<uint8_t>& getDynamicKey() const { return dynamic_key_; }
    uint32_t getOpcodeObfuscationKey() const { return opcode_obfuscation_key_; }

    // Debug string representation
    std::string toString() const;
}; 