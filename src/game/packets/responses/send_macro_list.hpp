#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <string>
#include <vector>

// TODO: The following structures are placeholders for a full macro system
// implementation. Based on the L2J Mobius implementation.
/*
struct MacroCmd
{
    uint8_t entry;     // 1-based order
    uint8_t type;      // 1 = skill, 3 = action, 4 = shortcut
    uint32_t d1;       // skill id / action id
    uint8_t d2;        // shortcut id
    std::wstring cmd;  // command name
};

struct Macro
{
    uint32_t id;
    std::wstring name;
    std::wstring descr;
    std::wstring acronym;
    uint8_t icon;
    std::vector<MacroCmd> commands;
};
*/

// SendMacroList - Server response with player's macro list
// Sends macro data to update the client's macro window
// For now, sends an empty list - TODO: implement full macro system
class SendMacroList : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xE7; // SendMacroList - Interlude Update 3
    uint32_t m_revision;

public:
    // Constructor - create with revision number
    explicit SendMacroList(uint32_t revision = 1);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
}; 