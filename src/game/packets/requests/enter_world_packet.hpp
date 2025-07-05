#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <vector>

// EnterWorld - Client request to enter the game world after character selection
class EnterWorldPacket : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x03; // EnterWorld - Interlude Update 3
    
    // Packet data fields (following L2J structure)
    std::vector<uint8_t> unknown_data_1_;  // 32 bytes
    uint32_t unknown_value_1_;             // Unknown integer
    uint32_t unknown_value_2_;             // Unknown integer  
    uint32_t unknown_value_3_;             // Unknown integer
    uint32_t unknown_value_4_;             // Unknown integer
    std::vector<uint8_t> unknown_data_2_;  // 32 bytes
    uint32_t unknown_value_5_;             // Unknown integer
    std::vector<std::vector<uint8_t>> tracert_data_; // 5x4 bytes (network routing)

public:
    EnterWorldPacket() = default;

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    bool isValid() const;
    
    // Getters for packet data (for debugging/logging)
    const std::vector<uint8_t>& getUnknownData1() const { return unknown_data_1_; }
    const std::vector<uint8_t>& getUnknownData2() const { return unknown_data_2_; }
    const std::vector<std::vector<uint8_t>>& getTracertData() const { return tracert_data_; }
    
    // Debug method
    std::string toString() const;
};