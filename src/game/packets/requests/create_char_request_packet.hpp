#pragma once

#include "../../../core/packets/packet.hpp"
#include "../../../core/network/packet_buffer.hpp"
#include <cstdint>
#include <string>

class CreateCharRequestPacket : public ReadablePacket
{
private:
    static constexpr uint8_t PACKET_ID = 0x0B;
    
    // Character creation data
    std::string character_name_;
    uint32_t race_;
    uint32_t sex_;
    uint32_t class_id_;
    uint32_t int_;
    uint32_t str_;
    uint32_t dex_;
    uint32_t con_;
    uint32_t men_;
    uint32_t wit_;
    uint32_t chr_;
    uint32_t hair_style_;
    uint32_t hair_color_;
    uint32_t face_;

public:
    CreateCharRequestPacket() = default;

    uint8_t getPacketId() const override;
    std::optional<uint16_t> getExPacketId() const override;
    void read(ReadablePacketBuffer &buffer) override;

    bool isValid() const;
    
    // Getters for character creation data
    const std::string& getCharacterName() const { return character_name_; }
    uint32_t getRace() const { return race_; }
    uint32_t getSex() const { return sex_; }
    uint32_t getClassId() const { return class_id_; }
    uint32_t getInt() const { return int_; }
    uint32_t getDex() const { return dex_; }
    uint32_t getCon() const { return con_; }
    uint32_t getMen() const { return men_; }
    uint32_t getWit() const { return wit_; }
    uint32_t getChr() const { return chr_; }
    uint32_t getHairStyle() const { return hair_style_; }
    uint32_t getHairColor() const { return hair_color_; }
    uint32_t getFace() const { return face_; }

    // Pretty-print all parsed values (for debugging)
    std::string toString() const;
};