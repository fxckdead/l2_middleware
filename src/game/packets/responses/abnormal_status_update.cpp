#include "abnormal_status_update.hpp"
#include <iostream>

// Constructor
AbnormalStatusUpdate::AbnormalStatusUpdate(const Player* player)
    : player_(player)
{
    if (!player_)
    {
        throw std::invalid_argument("Player cannot be null for AbnormalStatusUpdate packet");
    }
    buildEffectList();
}

void AbnormalStatusUpdate::write(SendablePacketBuffer& buffer)
{
    std::cout << "[AbnormalStatusUpdate] Sending status effects for: " << player_->getName() 
              << " (" << effects_.size() << " effects)" << std::endl;

    // 1. Effect count (short = 2 bytes)
    buffer.writeUInt16(static_cast<uint16_t>(effects_.size()));
    
    // 2. Effect data (exactly matching L2J Mobius)
    for (const auto& effect : effects_)
    {
        buffer.writeUInt32(effect.skillId);    // int = 4 bytes (skill display ID)
        buffer.writeUInt16(effect.skillLevel); // short = 2 bytes (skill display level)
        buffer.writeUInt32(effect.duration);   // int = 4 bytes (time remaining)
    }

    std::cout << "[AbnormalStatusUpdate] Status effects sent successfully" << std::endl;
}

size_t AbnormalStatusUpdate::getSize() const
{
    // Calculate packet size: 2 bytes for count + 10 bytes per effect (4+2+4)
    return 2 + (effects_.size() * 10);
}

void AbnormalStatusUpdate::buildEffectList()
{
    // For now, return empty effect list since we don't have a buff/debuff system implemented
    // TODO: Implement actual effect loading from player buffs/debuffs
    effects_.clear();
    
    // Example effects (commented out for now):
    /*
    // Example buff effect
    effects_.push_back({
        1001,   // skillId (example buff)
        1,      // skillLevel
        300,    // duration (5 minutes in seconds)
        1       // abnormalType (buff)
    });
    
    // Example debuff effect
    effects_.push_back({
        2001,   // skillId (example debuff)
        1,      // skillLevel
        60,     // duration (1 minute in seconds)
        2       // abnormalType (debuff)
    });
    */
} 