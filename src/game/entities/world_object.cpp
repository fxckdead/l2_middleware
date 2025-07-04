#include "world_object.hpp"

WorldObject::WorldObject(uint32_t objectId)
    : objectId_(objectId)
    , x_(0)
    , y_(0)
    , z_(0)
    , heading_(0)
{
}

void WorldObject::setPosition(int32_t x, int32_t y, int32_t z)
{
    x_ = x;
    y_ = y;
    z_ = z;
}

void WorldObject::setHeading(int32_t heading)
{
    heading_ = heading;
} 