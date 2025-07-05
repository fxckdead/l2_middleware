#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <string>
#include <vector>

// ExShowScreenMessage - Server response with screen messages
// Shows popup messages on the client screen (welcome messages, announcements, etc.)
class ExShowScreenMessage : public SendablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0xFE;      // Extended packet prefix
    static constexpr uint16_t EX_PACKET_ID = 0x38;  // Extended packet sub-opcode
    
    // Positions (matches L2J Mobius)
    enum class Position {
        TOP_LEFT = 1,
        TOP_CENTER = 2,
        TOP_RIGHT = 3,
        MIDDLE_LEFT = 4,
        MIDDLE_CENTER = 5,
        MIDDLE_RIGHT = 6,
        BOTTOM_CENTER = 7,
        BOTTOM_RIGHT = 8
    };
    
    int32_t type_;           // 0 - System Message, 1 - Text, 2 - NPC String
    int32_t sysMessageId_;   // System message ID (-1 for text)
    int32_t position_;       // Position on screen
    int32_t unk1_;           // Unknown field
    int32_t size_;           // Font size (0 - normal, 1 - small)
    int32_t unk2_;           // Unknown field
    int32_t unk3_;           // Unknown field
    bool effect_;            // Show effect (upper effect)
    int32_t time_;           // Display time
    bool fade_;              // Fade effect
    std::string text_;       // Text to display
    std::vector<std::string> parameters_; // String parameters

public:
    // Constructor - simple text message
    explicit ExShowScreenMessage(const std::string& text, int32_t time);
    
    // Constructor - text with position
    explicit ExShowScreenMessage(const std::string& text, int32_t position, int32_t time);
    
    // Constructor - full control
    explicit ExShowScreenMessage(const std::string& text, int32_t position, int32_t time, 
                                int32_t size, bool fade, bool showEffect);
    
    // Constructor - system message
    explicit ExShowScreenMessage(int32_t sysMessageId, int32_t position, int32_t time, 
                                const std::vector<std::string>& params = {});
    
    // Add string parameter
    void addStringParameter(const std::string& param);
    void addStringParameter(const std::vector<std::string>& params);

    // SendablePacket interface implementation
    uint8_t getPacketId() const override { return PACKET_ID; }
    uint16_t getExtendedPacketId() const override { return EX_PACKET_ID; }
    void write(SendablePacketBuffer &buffer) override;
    size_t getSize() const override;
}; 