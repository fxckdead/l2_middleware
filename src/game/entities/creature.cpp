#include "creature.hpp"

Creature::Creature(uint32_t objectId, const std::string& name)
    : WorldObject(objectId)
    , name_(name)
    , level_(1)
    , exp_(0)
    , sp_(0)
    , currentHp_(100.0)
    , maxHp_(100.0)
    , currentMp_(100.0)
    , maxMp_(100.0)
    , currentCp_(0.0)
    , maxCp_(0.0)
    , str_(10)
    , dex_(10)
    , con_(10)
    , int_(10)
    , wit_(10)
    , men_(10)
{
} 