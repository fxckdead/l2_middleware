#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include "../../entities/player.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

// CreatureSay - Server response for chat messages
// Handles all types of chat messages (say, shout, whisper, etc.)
// Based on L2J Mobius CreatureSay.java implementation
class CreatureSay : public SendablePacket
{
public:
    // Chat type constants from L2J Mobius ChatType enum
    enum class ChatType : uint32_t
    {
        GENERAL = 0,        // General chat
        SHOUT = 1,          // Shout chat
        WHISPER = 2,        // Private message
        PARTY = 3,          // Party chat
        CLAN = 4,           // Clan chat
        GM = 5,             // GM chat
        PETITION_PLAYER = 6, // Petition player
        PETITION_GM = 7,    // Petition GM
        TRADE = 8,          // Trade chat
        ALLIANCE = 9,       // Alliance chat
        ANNOUNCEMENT = 10,  // Announcement
        BOAT = 11,          // Boat chat
        FRIEND = 12,        // Friend chat
        MSNCHAT = 13,       // MSN chat
        PARTYMATCH_ROOM = 14, // Party match room
        PARTYROOM_COMMANDER = 15, // Party room commander
        PARTYROOM_ALL = 16, // Party room all
        HERO_VOICE = 17,    // Hero voice
        CRITICAL_ANNOUNCE = 18, // Critical announcement
        SCREEN_ANNOUNCE = 19,   // Screen announcement
        BATTLEFIELD = 20,   // Battlefield chat
        MPCC_ROOM = 21     // Multi-party command channel
    };

private:
    static constexpr uint8_t PACKET_ID = 0x4A; // CreatureSay - Interlude Update 3
    
    uint32_t m_objectId;
    ChatType m_chatType;
    std::string m_senderName;
    std::string m_text;
    uint32_t m_charId;
    uint32_t m_messageId;
    std::vector<std::string> m_parameters;

public:
    // Constructor with creature, chat type, sender name, and text
    CreatureSay(const Player* sender, ChatType chatType, const std::string& senderName, const std::string& text);
    
    // Constructor with creature, chat type, and text (uses creature's name)
    CreatureSay(const Player* sender, ChatType chatType, const std::string& text);
    
    // Constructor for system messages
    CreatureSay(ChatType chatType, uint32_t charId, uint32_t messageId);
    
    // Add string parameter for system messages
    void addStringParameter(const std::string& text);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    std::optional<uint16_t> getExPacketId() const override { return std::nullopt; }
    void write(SendablePacketBuffer& buffer) override;
    size_t getSize() const override;
    
private:
    // Helper method to get chat type client ID
    uint32_t getChatTypeClientId() const;
    
    // Helper method to get chat type name for logging
    const char* getChatTypeName() const;
}; 