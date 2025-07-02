#include "create_char_request_packet.hpp"
#include <stdexcept>
#include <sstream>
#include <cctype>
#include <locale>
#include <codecvt>

uint8_t CreateCharRequestPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> CreateCharRequestPacket::getExPacketId() const
{
    return std::nullopt;
}

void CreateCharRequestPacket::read(ReadablePacketBuffer &buffer)
{
    try
    {
        // --- Name (variable length UTF-16LE, null-terminated) ---
        std::u16string raw_name;

        while (buffer.getRemainingLength() >= 2)
        {
            uint16_t ch = buffer.readUInt16();
            if (ch == 0)
            {
                break; // reached null terminator
            }
            raw_name += static_cast<char16_t>(ch);
        }

        // Convert UTF-16 to UTF-8
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
        character_name_ = converter.to_bytes(raw_name);

        // Read remaining fields using buffer methods
        race_ = buffer.readUInt32();
        sex_ = buffer.readUInt32();
        class_id_ = buffer.readUInt32();

        // Read the 6 stat fields individually (as per Java implementation)
        int_ = buffer.readUInt32(); // intelligence
        str_ = buffer.readUInt32(); // strength
        con_ = buffer.readUInt32(); // constitution
        men_ = buffer.readUInt32(); // mental
        dex_ = buffer.readUInt32(); // dexterity
        wit_ = buffer.readUInt32(); // wisdom

        // Appearance fields
        hair_style_ = buffer.readUInt32();
        hair_color_ = buffer.readUInt32();
        face_ = buffer.readUInt32();

        // chr_ is not part of the packet, default to 0
        chr_ = 0;
    }
    catch (const std::exception &e)
    {
        // Reset values on error
        character_name_ = "";
        race_ = sex_ = class_id_ = 0;
        int_ = str_ = dex_ = con_ = men_ = wit_ = chr_ = 0;
        hair_style_ = hair_color_ = face_ = 0;

        throw std::runtime_error("Failed to parse CreateCharRequestPacket: " + std::string(e.what()));
    }
}

bool CreateCharRequestPacket::isValid() const
{
    // Name validation (as per Java implementation)
    if (character_name_.length() < 1 || character_name_.length() > 16)
    {
        return false;
    }

    // Basic alphanumeric check (simplified version of StringUtil.isAlphaNumeric)
    for (char c : character_name_)
    {
        if (!std::isalnum(static_cast<unsigned char>(c)))
        {
            return false;
        }
    }

    // Validate race (0=Human, 1=Elf, 2=DarkElf, 3=Orc, 4=Dwarf)
    if (race_ > 4)
    {
        return false;
    }

    // Validate sex (0=Male, 1=Female)
    if (sex_ > 1)
    {
        return false;
    }

    // Validate face (as per Java implementation: 0-2)
    if (face_ > 2)
    {
        return false;
    }

    // Validate hair style (as per Java implementation)
    bool is_female = (sex_ == 1);
    if (hair_style_ < 0)
    {
        return false;
    }
    if (!is_female && hair_style_ > 4) // Male: 0-4
    {
        return false;
    }
    if (is_female && hair_style_ > 6) // Female: 0-6
    {
        return false;
    }

    // Validate hair color (as per Java implementation: 0-3)
    if (hair_color_ > 3)
    {
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------------
// Debug helper
// -----------------------------------------------------------------------------

std::string CreateCharRequestPacket::toString() const
{
    std::ostringstream oss;
    oss << "CreateCharRequestPacket["
        << "name=" << character_name_
        << ", race=" << race_
        << ", sex=" << sex_
        << ", classId=" << class_id_
        << ", hairStyle=" << hair_style_
        << ", hairColor=" << hair_color_
        << ", face=" << face_
        << ", str=" << str_
        << ", int=" << int_
        << ", con=" << con_
        << ", men=" << men_
        << ", dex=" << dex_
        << ", wit=" << wit_
        << "]";
    return oss.str();
}