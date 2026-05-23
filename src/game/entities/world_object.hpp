#pragma once

#include <cstdint>

// Base class for all game objects (players, NPCs, items, etc.)
class WorldObject
{
protected:
    uint32_t objectId_;
    int32_t x_;
    int32_t y_;
    int32_t z_;
    int32_t heading_;

public:
    WorldObject(uint32_t objectId);
    virtual ~WorldObject() = default;

    // Getters
    uint32_t getObjectId() const { return objectId_; }
    int32_t getX() const { return x_; }
    int32_t getY() const { return y_; }
    int32_t getZ() const { return z_; }
    int32_t getHeading() const { return heading_; }

    // Setters
    void setPosition(int32_t x, int32_t y, int32_t z);
    void setHeading(int32_t heading);
    void setObjectId(uint32_t objectId) { objectId_ = objectId; }
}; 