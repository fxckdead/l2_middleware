#include "enter_world_packet.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>

uint8_t EnterWorldPacket::getPacketId() const
{
    return PACKET_ID;
}

std::optional<uint16_t> EnterWorldPacket::getExPacketId() const
{
    return std::nullopt;
}

void EnterWorldPacket::read(ReadablePacketBuffer &buffer)
{
    // 1. Read 32 bytes of unknown data
    unknown_data_1_.resize(32);
    for (int i = 0; i < 32; i++)
    {
        unknown_data_1_[i] = buffer.readByte();
    }
    
    // 2. Read 4 unknown integers
    unknown_value_1_ = buffer.readInt32();
    unknown_value_2_ = buffer.readInt32();
    unknown_value_3_ = buffer.readInt32();
    unknown_value_4_ = buffer.readInt32();
    
    // 3. Read another 32 bytes of unknown data
    unknown_data_2_.resize(32);
    for (int i = 0; i < 32; i++)
    {
        unknown_data_2_[i] = buffer.readByte();
    }
    
    // 4. Read 1 unknown integer
    unknown_value_5_ = buffer.readInt32();
    
    // 5. Read 5x4 bytes of tracert data (network routing information)
    tracert_data_.resize(5);
    for (int i = 0; i < 5; i++)
    {
        tracert_data_[i].resize(4);
        for (int j = 0; j < 4; j++)
        {
            tracert_data_[i][j] = buffer.readByte();
        }
    }
}

bool EnterWorldPacket::isValid() const
{
    // Basic validation - check if we have the expected data sizes
    return unknown_data_1_.size() == 32 && 
           unknown_data_2_.size() == 32 && 
           tracert_data_.size() == 5 &&
           tracert_data_[0].size() == 4;
}

std::string EnterWorldPacket::toString() const
{
    std::stringstream ss;
    ss << "EnterWorldPacket [";
    ss << "Unknown1: " << unknown_value_1_ << ", ";
    ss << "Unknown2: " << unknown_value_2_ << ", ";
    ss << "Unknown3: " << unknown_value_3_ << ", ";
    ss << "Unknown4: " << unknown_value_4_ << ", ";
    ss << "Unknown5: " << unknown_value_5_;
    
    // Add tracert data summary
    ss << ", Tracert: ";
    for (size_t i = 0; i < tracert_data_.size() && i < 2; i++) // Show first 2 entries
    {
        ss << "[";
        for (size_t j = 0; j < tracert_data_[i].size(); j++)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(tracert_data_[i][j]);
            if (j < tracert_data_[i].size() - 1) ss << ".";
        }
        ss << "]";
        if (i < tracert_data_.size() - 1 && i < 1) ss << " ";
    }
    if (tracert_data_.size() > 2) ss << "...";
    
    ss << "]";
    return ss.str();
}