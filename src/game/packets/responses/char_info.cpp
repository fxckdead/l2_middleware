#include "char_info.hpp"
#include <iostream>

CharInfo::CharInfo(const Player* player, bool gm_see_invis)
    : player_(player), gm_see_invis_(gm_see_invis) {
    
    obj_id_ = player->getObjectId();
    x_ = player->getX();
    y_ = player->getY();
    z_ = player->getZ();
    heading_ = player->getHeading();
    
    // Combat stats
    m_atk_spd_ = player->getMAtkSpd();
    p_atk_spd_ = static_cast<int>(player->getPAtkSpd());
    
    // Movement speeds
    move_multiplier_ = player->getMovementSpeedMultiplier();
    run_spd_ = static_cast<int>(player->getRunSpeed() / move_multiplier_);
    walk_spd_ = static_cast<int>(player->getWalkSpeed() / move_multiplier_);
    swim_run_spd_ = static_cast<int>(player->getSwimRunSpeed() / move_multiplier_);
    swim_walk_spd_ = static_cast<int>(player->getSwimWalkSpeed() / move_multiplier_);
    fly_run_spd_ = player->isFlying() ? run_spd_ : 0;
    fly_walk_spd_ = player->isFlying() ? walk_spd_ : 0;
    
    vehicle_id_ = 0; // No vehicle support yet
}

void CharInfo::write(SendablePacketBuffer& buffer) {
    buffer.writeInt32(x_);
    buffer.writeInt32(y_);
    buffer.writeInt32(z_);
    buffer.writeInt32(vehicle_id_);
    buffer.writeInt32(obj_id_);
    
    // Character appearance
    buffer.writeCUtf16leString(player_->getName());
    buffer.writeInt32(static_cast<int>(player_->getRace()));
    buffer.writeInt32(player_->isFemale() ? 1 : 0);
    buffer.writeInt32(player_->getBaseClass());
    
    // Equipment paperdoll slots (12 items)
    buffer.writeInt32(0); // PAPERDOLL_UNDER
    buffer.writeInt32(0); // PAPERDOLL_HEAD
    buffer.writeInt32(0); // PAPERDOLL_RHAND
    buffer.writeInt32(0); // PAPERDOLL_LHAND
    buffer.writeInt32(0); // PAPERDOLL_GLOVES
    buffer.writeInt32(0); // PAPERDOLL_CHEST
    buffer.writeInt32(0); // PAPERDOLL_LEGS
    buffer.writeInt32(0); // PAPERDOLL_FEET
    buffer.writeInt32(0); // PAPERDOLL_CLOAK
    buffer.writeInt32(0); // PAPERDOLL_RHAND (duplicate)
    buffer.writeInt32(0); // PAPERDOLL_HAIR
    buffer.writeInt32(0); // PAPERDOLL_HAIR2
    
    // C6 new shorts (8 shorts)
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    
    // Augmentation
    buffer.writeInt32(0); // PAPERDOLL_RHAND augmentation
    
    // More shorts (12 shorts)
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    
    // Another augmentation
    buffer.writeInt32(0); // PAPERDOLL_RHAND augmentation (duplicate)
    
    // Final shorts (4 shorts)
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    buffer.writeUInt16(0);
    
    // PvP and Karma
    buffer.writeInt32(player_->getPvpFlag());
    buffer.writeInt32(player_->getKarma());
    
    // Combat stats
    buffer.writeInt32(m_atk_spd_);
    buffer.writeInt32(p_atk_spd_);
    
    // PvP and Karma (duplicate)
    buffer.writeInt32(player_->getPvpFlag());
    buffer.writeInt32(player_->getKarma());
    
    // Movement speeds
    buffer.writeInt32(run_spd_);
    buffer.writeInt32(walk_spd_);
    buffer.writeInt32(swim_run_spd_);
    buffer.writeInt32(swim_walk_spd_);
    buffer.writeInt32(fly_run_spd_);
    buffer.writeInt32(fly_walk_spd_);
    buffer.writeInt32(fly_run_spd_);  // duplicate
    buffer.writeInt32(fly_walk_spd_); // duplicate
    
    // Multipliers
    buffer.writeFloat64(move_multiplier_);
    buffer.writeFloat64(player_->getAttackSpeedMultiplier());
    buffer.writeFloat64(player_->getCollisionRadius());
    buffer.writeFloat64(player_->getCollisionHeight());
    
    // Appearance
    buffer.writeInt32(player_->getHairStyle());
    buffer.writeInt32(player_->getHairColor());
    buffer.writeInt32(player_->getFace());
    buffer.writeCUtf16leString(gm_see_invis_ ? "Invisible" : player_->getTitle());
    
    // Clan info (no cursed weapon support)
    buffer.writeInt32(player_->getClanId());
    buffer.writeInt32(player_->getClanCrestId());
    buffer.writeInt32(player_->getAllyId());
    buffer.writeInt32(player_->getAllyCrestId());
    
    // Relation (placeholder)
    buffer.writeInt32(0);
    
    // Status flags
    buffer.writeUInt8(player_->isSitting() ? 0 : 1); // standing = 1, sitting = 0
    buffer.writeUInt8(player_->isRunning() ? 1 : 0); // running = 1, walking = 0
    buffer.writeUInt8(player_->isInCombat() ? 1 : 0);
    buffer.writeUInt8(player_->isAlikeDead() ? 1 : 0);
    buffer.writeUInt8((!gm_see_invis_ && player_->isInvisible()) ? 1 : 0);
    buffer.writeUInt8(0); // mount type (0 = no mount)
    buffer.writeUInt8(0); // private store type
    
    // Cubics
    buffer.writeUInt16(0); // cubic count
    
    // More status
    buffer.writeUInt8(0); // party match room
    buffer.writeInt32(gm_see_invis_ ? (player_->getAbnormalVisualEffects() | 0x800000) : player_->getAbnormalVisualEffects());
    buffer.writeUInt8(player_->getRecomLeft());
    buffer.writeUInt16(player_->getRecomHave());
    buffer.writeInt32(player_->getPlayerClass());
    buffer.writeInt32(player_->getMaxCp());
    buffer.writeInt32(static_cast<int>(player_->getCurrentCp()));
    buffer.writeUInt8(0); // enchant effect
    buffer.writeUInt8(0); // team id
    buffer.writeInt32(player_->getClanCrestLargeId());
    buffer.writeUInt8(player_->isNoble() ? 1 : 0);
    buffer.writeUInt8(player_->isHero() ? 1 : 0);
    
    // Fishing
    buffer.writeUInt8(player_->isFishing() ? 1 : 0);
    buffer.writeInt32(player_->getFishX());
    buffer.writeInt32(player_->getFishY());
    buffer.writeInt32(player_->getFishZ());
    
    // Final appearance
    buffer.writeInt32(player_->getNameColor());
    buffer.writeInt32(heading_);
    buffer.writeInt32(player_->getPledgeClass());
    buffer.writeInt32(player_->getPledgeType());
    buffer.writeInt32(player_->getTitleColor());
    buffer.writeInt32(0); // cursed weapon level
}

size_t CharInfo::getSize() const {
    // Calculate packet size based on L2J Mobius CharInfo structure
    size_t size = 0;
    
    // Basic position and object data
    size += 4 * 5; // x, y, z, vehicle_id, obj_id
    
    // Character name (string)
    size += 2 + (player_->getName().length() * 2); // UTF-16 string
    
    // Character basic info
    size += 4 * 4; // race, sex, base_class
    
    // Equipment paperdoll (12 items)
    size += 4 * 12;
    
    // C6 shorts and augmentation
    size += 2 * 4; // 4 shorts
    size += 4; // augmentation
    size += 2 * 12; // 12 shorts
    size += 4; // augmentation duplicate
    size += 2 * 4; // 4 final shorts
    
    // PvP, karma, combat stats
    size += 4 * 6; // pvp_flag, karma, m_atk_spd, p_atk_spd, pvp_flag2, karma2
    
    // Movement speeds
    size += 4 * 8; // 8 movement speed values
    
    // Multipliers
    size += 8 * 4; // 4 double values
    
    // Appearance
    size += 4 * 3; // hair_style, hair_color, face
    
    // Title (string)
    size += 2 + (player_->getTitle().length() * 2); // UTF-16 string
    
    // Clan info
    size += 4 * 4; // clan_id, clan_crest_id, ally_id, ally_crest_id
    
    // Relation
    size += 4;
    
    // Status flags
    size += 1 * 7; // 7 status bytes
    
    // Cubics
    size += 2; // cubic count (0 for now)
    
    // More status
    size += 1; // party match room
    size += 4; // abnormal visual effects
    size += 1; // recom left
    size += 2; // recom have
    size += 4; // player class
    size += 4; // max cp
    size += 4; // current cp
    size += 1; // enchant effect
    size += 1; // team id
    size += 4; // clan crest large id
    size += 1; // noble
    size += 1; // hero
    
    // Fishing
    size += 1; // is fishing
    size += 4 * 3; // fish x, y, z
    
    // Final appearance
    size += 4 * 5; // name_color, heading, pledge_class, pledge_type, title_color
    size += 4; // cursed weapon level
    
    return size;
} 