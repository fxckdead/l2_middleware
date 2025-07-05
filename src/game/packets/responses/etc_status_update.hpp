// src/game/packets/responses/etc_status_update.hpp
#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <memory>

// EtcStatusUpdate packet (opcode 0xF3)
// Sends status icons (weight, soulshots, etc.) to the client
class EtcStatusUpdate : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xF3;
    const Player* player_;
    
    // Status flags (matches L2J Mobius exactly - only 7 fields)
    uint32_t charges_;           // 1-7 increase force, level
    uint32_t weightPenalty_;     // 1-4 weight penalty, level (1=50%, 2=66.6%, 3=80%, 4=100%)
    uint32_t messageRefusal_;    // 1 = block all chat
    uint32_t dangerArea_;        // 1 = danger area
    uint32_t expertisePenalty_;  // Weapon Grade Penalty [1-4] - Armor Grade Penalty [1-4]
    uint32_t charmOfCourage_;    // 1 = charm of courage (allows resurrection on the same spot upon death on the siege battlefield)
    uint32_t deathPenalty_;      // 1-15 death penalty, level (combat ability decreased due to death)
    
    void calculateStatusFlags();

public:
    explicit EtcStatusUpdate(const Player* player);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    bool shouldWriteOpcodeAutomatically() const override { return true; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 