#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"

class CharInfo : public SendablePacket {
private:
    const Player* player_;
    int obj_id_;
    int x_;
    int y_;
    int z_;
    int heading_;
    int m_atk_spd_;
    int p_atk_spd_;
    int run_spd_;
    int walk_spd_;
    int swim_run_spd_;
    int swim_walk_spd_;
    int fly_run_spd_;
    int fly_walk_spd_;
    double move_multiplier_;
    int vehicle_id_;
    bool gm_see_invis_;

public:
    explicit CharInfo(const Player* player, bool gm_see_invis = false);
    
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
    
    uint8_t getPacketId() const override { return 0x03; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    
    static constexpr uint8_t PACKET_ID = 0x03;
}; 