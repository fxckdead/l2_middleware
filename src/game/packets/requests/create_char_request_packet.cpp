#include "create_char_request_packet.hpp"
#include <stdexcept>
#include <locale>
#include <codecvt>
#include <iostream>
#include <cstdio>

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
    // === HEX DUMP FOR DEBUGGING ===
    size_t total_size = buffer.getRemainingLength();
    printf("[CreateCharRequestPacket] === RAW PACKET DATA ===\n");
    printf("[CreateCharRequestPacket] Total size: %zu bytes\n", total_size);
    
    // Create a copy to peek at all data without consuming it
    std::vector<uint8_t> raw_data;
    size_t original_pos = buffer.getRemainingLength();
    
    for (size_t i = 0; i < total_size; ++i) {
        raw_data.push_back(buffer.readByte());
    }
    
    // Print hex dump in 16-byte rows
    for (size_t i = 0; i < raw_data.size(); i += 16) {
        printf("[CreateCharRequestPacket] %04zX: ", i);
        
        // Print hex values
        for (size_t j = 0; j < 16 && (i + j) < raw_data.size(); ++j) {
            printf("%02X ", raw_data[i + j]);
        }
        
        // Pad if last row is incomplete
        for (size_t j = raw_data.size() - i; j < 16; ++j) {
            printf("   ");
        }
        
        printf(" | ");
        
        // Print ASCII representation
        for (size_t j = 0; j < 16 && (i + j) < raw_data.size(); ++j) {
            uint8_t byte = raw_data[i + j];
            if (byte >= 32 && byte <= 126) {
                printf("%c", byte);
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
    printf("[CreateCharRequestPacket] === END HEX DUMP ===\n");
    
    try {
        if (raw_data.empty()) {
            throw std::runtime_error("CreateCharRequestPacket: empty payload");
        }

        // In game packets the opcode has already been removed by PacketFactory,
        // so the UTF-16 name starts at byte 0.
        size_t data_offset = 0;
        
        // Parse the name field from raw data manually
        std::u16string raw_name;
        
        // Read UTF-16LE name until null terminator
        while (data_offset + 1 < raw_data.size()) {
            uint16_t ch = static_cast<uint16_t>(raw_data[data_offset]) | 
                         (static_cast<uint16_t>(raw_data[data_offset + 1]) << 8);
            data_offset += 2;
            
            if (ch == 0) {
                break; // null terminator found
            }
            raw_name += static_cast<char16_t>(ch);
        }
        
        // Convert UTF-16 to UTF-8
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
        character_name_ = converter.to_bytes(raw_name);
        
        printf("[CreateCharRequestPacket] Parsed name: '%s' (consumed %zu bytes)\n", 
               character_name_.c_str(), data_offset);
        
        // Read integer fields from remaining data
        if (data_offset + 4 <= raw_data.size()) {
            race_ = static_cast<uint32_t>(raw_data[data_offset]) |
                   (static_cast<uint32_t>(raw_data[data_offset + 1]) << 8) |
                   (static_cast<uint32_t>(raw_data[data_offset + 2]) << 16) |
                   (static_cast<uint32_t>(raw_data[data_offset + 3]) << 24);
            data_offset += 4;
            printf("[CreateCharRequestPacket] Race at offset %zu: %u\n", data_offset - 4, race_);
        } else {
            race_ = 0;
        }
        
        if (data_offset + 4 <= raw_data.size()) {
            sex_ = static_cast<uint32_t>(raw_data[data_offset]) |
                  (static_cast<uint32_t>(raw_data[data_offset + 1]) << 8) |
                  (static_cast<uint32_t>(raw_data[data_offset + 2]) << 16) |
                  (static_cast<uint32_t>(raw_data[data_offset + 3]) << 24);
            data_offset += 4;
            printf("[CreateCharRequestPacket] Sex at offset %zu: %u\n", data_offset - 4, sex_);
        } else {
            sex_ = 0;
        }
        
        if (data_offset + 4 <= raw_data.size()) {
            class_id_ = static_cast<uint32_t>(raw_data[data_offset]) |
                       (static_cast<uint32_t>(raw_data[data_offset + 1]) << 8) |
                       (static_cast<uint32_t>(raw_data[data_offset + 2]) << 16) |
                       (static_cast<uint32_t>(raw_data[data_offset + 3]) << 24);
            data_offset += 4;
            printf("[CreateCharRequestPacket] Class ID at offset %zu: %u\n", data_offset - 4, class_id_);
        } else {
            class_id_ = 0;
        }
        
        // Set remaining fields to defaults
        int_ = chr_ = con_ = men_ = dex_ = wit_ = 0;
        hair_style_ = hair_color_ = face_ = 0;
        
        printf("[CreateCharRequestPacket] Parsing complete - used %zu of %zu bytes\n", 
               data_offset, raw_data.size());
        
    } catch (const std::exception& e) {
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
    if (character_name_.empty() || character_name_.length() > 16) {
        return false;
    }
    
    // Validate race (0=Human, 1=Elf, 2=DarkElf, 3=Orc, 4=Dwarf)
    if (race_ > 4) {
        return false;
    }
    
    // Validate sex (0=Male, 1=Female)
    if (sex_ > 1) {
        return false;
    }
    
    return true;
}