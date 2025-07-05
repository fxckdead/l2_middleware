#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <string>
#include <vector>

// SystemMessage - Server response with system messages
// Shows system messages to the client (welcome messages, notifications, etc.)
class SystemMessage : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x64; // SystemMessage - Interlude Update 3
    
    // Parameter types (matches L2J Mobius)
    enum class ParamType {
        TYPE_TEXT = 0,
        TYPE_INT_NUMBER = 1,
        TYPE_NPC_NAME = 2,
        TYPE_ITEM_NAME = 3,
        TYPE_SKILL_NAME = 4,
        TYPE_CASTLE_NAME = 5,
        TYPE_LONG_NUMBER = 6,
        TYPE_ZONE_NAME = 7,
        TYPE_ELEMENT_NAME = 9,
        TYPE_INSTANCE_NAME = 10,
        TYPE_DOOR_NAME = 11,
        TYPE_PLAYER_NAME = 12,
        TYPE_SYSTEM_STRING = 13
    };
    
    // Parameter data structure
    struct ParamData {
        ParamType type;
        std::string stringValue;
        int32_t intValue;
        int64_t longValue;
        std::vector<int32_t> intArrayValue;
    };
    
    int32_t messageId_;
    std::vector<ParamData> parameters_;
    
    void addParameter(ParamType type, const std::string& value);
    void addParameter(ParamType type, int32_t value);
    void addParameter(ParamType type, int64_t value);
    void addParameter(ParamType type, const std::vector<int32_t>& values);

public:
    // Constructor - create with message ID
    explicit SystemMessage(int32_t messageId);
    
    // Constructor - create with text message
    explicit SystemMessage(const std::string& text);
    
    // Parameter methods (matches L2J Mobius)
    SystemMessage& addString(const std::string& text);
    SystemMessage& addInt(int32_t number);
    SystemMessage& addLong(int64_t number);
    SystemMessage& addPlayerName(const std::string& playerName);
    SystemMessage& addNpcName(int32_t npcId);
    SystemMessage& addItemName(int32_t itemId);
    SystemMessage& addSkillName(int32_t skillId, int32_t skillLevel);
    SystemMessage& addZoneName(int32_t x, int32_t y, int32_t z);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 