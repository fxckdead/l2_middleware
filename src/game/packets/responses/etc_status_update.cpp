#include "etc_status_update.hpp"
#include <iostream>

EtcStatusUpdate::EtcStatusUpdate(const Player* player)
    : player_(player)
{
    if (!player_) {
        throw std::invalid_argument("Player cannot be null for EtcStatusUpdate packet");
    }
    calculateStatusFlags();
}

void EtcStatusUpdate::write(SendablePacketBuffer& buffer)
{
    // Packet structure: 7 status flags as uint32 values (matches L2J Mobius exactly)
    buffer.writeInt32(static_cast<int32_t>(charges_));
    buffer.writeInt32(static_cast<int32_t>(weightPenalty_));
    buffer.writeInt32(static_cast<int32_t>(messageRefusal_));
    buffer.writeInt32(static_cast<int32_t>(dangerArea_));
    buffer.writeInt32(static_cast<int32_t>(expertisePenalty_));
    buffer.writeInt32(static_cast<int32_t>(charmOfCourage_));
    buffer.writeInt32(static_cast<int32_t>(deathPenalty_));
}

size_t EtcStatusUpdate::getSize() const
{
    // Fixed size: 7 uint32 fields = 28 bytes
    return 28;
}

void EtcStatusUpdate::calculateStatusFlags()
{
    // For now, set all flags to 0 (no active status effects)
    // TODO: Implement actual status calculation based on player state
    
    charges_ = 0;           // TODO: player_.getCharges()
    weightPenalty_ = 0;     // TODO: player_.getWeightPenalty()
    messageRefusal_ = 0;    // TODO: player_.getMessageRefusal() || player_.isChatBanned() || player_.isSilenceMode()
    dangerArea_ = 0;        // TODO: player_.isInsideZone(ZoneId.DANGER_AREA)
    expertisePenalty_ = 0;  // TODO: (player_.getExpertiseWeaponPenalty() > 0) || (player_.getExpertiseArmorPenalty() > 0)
    charmOfCourage_ = 0;    // TODO: player_.hasCharmOfCourage()
    deathPenalty_ = 0;      // TODO: player_.getDeathPenaltyBuffLevel()
} 