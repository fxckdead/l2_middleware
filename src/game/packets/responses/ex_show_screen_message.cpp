#include "ex_show_screen_message.hpp"
#include <iostream>

// Constructor - simple text message
ExShowScreenMessage::ExShowScreenMessage(const std::string& text, int32_t time)
    : type_(1), sysMessageId_(-1), position_(static_cast<int32_t>(Position::TOP_CENTER)), 
      unk1_(0), size_(0), unk2_(0), unk3_(0), effect_(false), time_(time), fade_(false), text_(text)
{
}

// Constructor - text with position
ExShowScreenMessage::ExShowScreenMessage(const std::string& text, int32_t position, int32_t time)
    : type_(1), sysMessageId_(-1), position_(position), 
      unk1_(0), size_(0), unk2_(0), unk3_(0), effect_(false), time_(time), fade_(false), text_(text)
{
}

// Constructor - full control
ExShowScreenMessage::ExShowScreenMessage(const std::string& text, int32_t position, int32_t time, 
                                         int32_t size, bool fade, bool showEffect)
    : type_(1), sysMessageId_(-1), position_(position), 
      unk1_(0), size_(size), unk2_(0), unk3_(0), effect_(showEffect), time_(time), fade_(fade), text_(text)
{
}

// Constructor - system message
ExShowScreenMessage::ExShowScreenMessage(int32_t sysMessageId, int32_t position, int32_t time, 
                                         const std::vector<std::string>& params)
    : type_(2), sysMessageId_(sysMessageId), position_(position), 
      unk1_(0), size_(0), unk2_(0), unk3_(0), effect_(false), time_(time), fade_(false), text_(""), parameters_(params)
{
}

void ExShowScreenMessage::write(SendablePacketBuffer &buffer)
{
    // Opcode is written automatically by base class

    std::cout << "[ExShowScreenMessage] Sending screen message: " << text_ << std::endl;

    // Following L2J Mobius ExShowScreenMessage.java structure EXACTLY
    
    // 1. Type (int)
    buffer.writeUInt32(static_cast<uint32_t>(type_));
    
    // 2. System message ID (int)
    buffer.writeUInt32(static_cast<uint32_t>(sysMessageId_));
    
    // 3. Position (int)
    buffer.writeUInt32(static_cast<uint32_t>(position_));
    
    // 4. Unknown 1 (int)
    buffer.writeUInt32(static_cast<uint32_t>(unk1_));
    
    // 5. Size (int)
    buffer.writeUInt32(static_cast<uint32_t>(size_));
    
    // 6. Unknown 2 (int)
    buffer.writeUInt32(static_cast<uint32_t>(unk2_));
    
    // 7. Unknown 3 (int)
    buffer.writeUInt32(static_cast<uint32_t>(unk3_));
    
    // 8. Effect (int)
    buffer.writeUInt32(static_cast<uint32_t>(effect_ ? 1 : 0));
    
    // 9. Time (int)
    buffer.writeUInt32(static_cast<uint32_t>(time_));
    
    // 10. Fade (int)
    buffer.writeUInt32(static_cast<uint32_t>(fade_ ? 1 : 0));
    
    // 11. Text (string)
    buffer.writeCUtf16leString(text_);
    
    // 12. Additional text or parameters
    if (sysMessageId_ == -1)
    {
        // For text messages, write the text again
        buffer.writeCUtf16leString(text_);
    }
    else if (!parameters_.empty())
    {
        // For system messages, write parameters
        for (const auto& param : parameters_)
        {
            buffer.writeCUtf16leString(param);
        }
    }

    std::cout << "[ExShowScreenMessage] Screen message sent successfully" << std::endl;
}

size_t ExShowScreenMessage::getSize() const
{
    // Calculate packet size based on L2J Mobius structure
    size_t size = 3; // Extended opcode (0xFE + 16-bit sub-opcode)

    // Fixed-size fields (11 ints)
    size += 4 * 11; // type, sysMessageId, position, unk1, size, unk2, unk3, effect, time, fade
    
    // Text
    size += (text_.length() + 1) * 2; // UTF-16LE + null
    
    // Additional text or parameters
    if (sysMessageId_ == -1)
    {
        // For text messages, write the text again
        size += (text_.length() + 1) * 2; // UTF-16LE + null
    }
    else if (!parameters_.empty())
    {
        // For system messages, write parameters
        for (const auto& param : parameters_)
        {
            size += (param.length() + 1) * 2; // UTF-16LE + null
        }
    }

    return size;
}

void ExShowScreenMessage::addStringParameter(const std::string& param)
{
    parameters_.push_back(param);
}

void ExShowScreenMessage::addStringParameter(const std::vector<std::string>& params)
{
    parameters_.insert(parameters_.end(), params.begin(), params.end());
} 