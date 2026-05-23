#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <vector>
#include <string>

// CharacterSelectionInfo - Server response after successful RequestLogin
// Shows available characters for the authenticated account
class CharacterSelectionInfo : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x13; // CharacterSelectionInfo - Interlude Update 3
    std::vector<Player *> characters_;

public:
    // Constructor - create with character data
    explicit CharacterSelectionInfo(const std::vector<Player *> &characters);

    // Create with characters from database
    static std::unique_ptr<CharacterSelectionInfo> createFromDatabase(class CharacterDatabaseManager *char_db, const std::string &account_name);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
};