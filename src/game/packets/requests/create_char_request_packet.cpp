#include "create_char_request_packet.hpp"
#include <stdexcept>
#include <locale>
#include <codecvt>
#include <iostream>
#include <cstdio>
#include <sstream>

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
    // Copy packet data
    size_t total_size = buffer.getRemainingLength();
    std::vector<uint8_t> raw_data;
    raw_data.reserve(total_size);
    for (size_t i = 0; i < total_size; ++i)
    {
        raw_data.push_back(buffer.readByte());
    }

    try
    {
        if (raw_data.size() < 56)
        {
            throw std::runtime_error("CreateCharRequestPacket: payload too small");
        }

        // --- Name (variable length UTF-16LE, null-terminated) ---
        std::u16string raw_name;
        size_t data_offset = 0;

        while (data_offset + 1 < raw_data.size())
        {
            uint16_t ch = static_cast<uint16_t>(raw_data[data_offset]) |
                          (static_cast<uint16_t>(raw_data[data_offset + 1]) << 8);
            data_offset += 2;

            if (ch == 0)
            {
                break; // reached terminator
            }

            raw_name += static_cast<char16_t>(ch);
        }

        if (data_offset + 28 > raw_data.size())
        {
            throw std::runtime_error("CreateCharRequestPacket: payload truncated after name");
        }

        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
        character_name_ = converter.to_bytes(raw_name);

        // --- Fixed numeric fields follow the name ---
        auto read_u32 = [&raw_data](size_t offset) -> uint32_t
        {
            return static_cast<uint32_t>(raw_data[offset]) |
                   (static_cast<uint32_t>(raw_data[offset + 1]) << 8) |
                   (static_cast<uint32_t>(raw_data[offset + 2]) << 16) |
                   (static_cast<uint32_t>(raw_data[offset + 3]) << 24);
        };

        race_ = read_u32(data_offset);
        data_offset += 4;
        sex_ = read_u32(data_offset);
        data_offset += 4;
        class_id_ = read_u32(data_offset);
        data_offset += 4;

        // Skip 24 bytes of unknown / reserved data
        data_offset += 24;

        if (data_offset + 12 > raw_data.size())
        {
            hair_style_ = hair_color_ = face_ = 0;
        }
        else
        {
            hair_style_ = read_u32(data_offset);
            data_offset += 4;
            hair_color_ = read_u32(data_offset);
            data_offset += 4;
            face_ = read_u32(data_offset);
        }

        // Stats (not transmitted by client during creation → default zeros)
        int_ = dex_ = con_ = men_ = wit_ = chr_ = 0;
    }
    catch (const std::exception &e)
    {
        // Reset values on error
        character_name_ = "";
        race_ = sex_ = class_id_ = 0;
        int_ = dex_ = con_ = men_ = wit_ = chr_ = 0;
        hair_style_ = hair_color_ = face_ = 0;

        throw std::runtime_error("Failed to parse CreateCharRequestPacket: " + std::string(e.what()));
    }
}

bool CreateCharRequestPacket::isValid() const
{
    // Basic validation
    if (character_name_.empty() || character_name_.length() > 16)
    {
        return false;
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
        << "]";
    return oss.str();
}