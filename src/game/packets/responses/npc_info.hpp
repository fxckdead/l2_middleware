#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <string>

// Forward declaration for future NPC entity class
class Npc;

// NpcInfo - Server response showing NPC information
// Tells the client about NPCs in the world (position, appearance, stats, etc.)
// Based on L2J Mobius AbstractNpcInfo.java NpcInfo implementation (simplified)
class NpcInfo : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x16; // NpcInfo - Interlude Update 3
    
    // Basic NPC data
    uint32_t m_objectId;
    uint32_t m_displayId;
    bool m_isAttackable;
    uint32_t m_x;
    uint32_t m_y;
    uint32_t m_z;
    uint32_t m_heading;
    uint32_t m_mAtkSpd;
    uint32_t m_pAtkSpd;
    uint32_t m_runSpd;
    uint32_t m_walkSpd;
    uint32_t m_swimRunSpd;
    uint32_t m_swimWalkSpd;
    uint32_t m_flyRunSpd;
    uint32_t m_flyWalkSpd;
    double m_moveMultiplier;
    double m_attackSpeedMultiplier;
    double m_collisionRadius;
    double m_collisionHeight;
    uint32_t m_rhand;
    uint32_t m_chest;
    uint32_t m_lhand;
    std::string m_name;
    std::string m_title;
    bool m_isRunning;
    bool m_isInCombat;
    bool m_isAlikeDead;
    bool m_isSummoned;
    uint32_t m_abnormalVisualEffects;
    uint32_t m_enchantEffect;
    bool m_isFlying;

public:
    // Constructor for basic NPC (for testing - creates a dummy NPC)
    NpcInfo(uint32_t objectId, uint32_t displayId, uint32_t x, uint32_t y, uint32_t z, 
            const std::string& name = "TestNPC", const std::string& title = "");

    // TODO: Constructor with actual NPC entity when implemented
    // NpcInfo(const Npc* npc, const Player* attacker);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 