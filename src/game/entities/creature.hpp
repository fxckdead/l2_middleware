#pragma once

#include "world_object.hpp"
#include <cstdint>
#include <string>

// Base class for all living entities (players, NPCs, monsters)
class Creature : public WorldObject
{
protected:
    std::string name_;
    uint32_t level_;
    uint64_t exp_;
    uint64_t sp_;
    
    // Stats
    double currentHp_;
    double maxHp_;
    double currentMp_;
    double maxMp_;
    double currentCp_;
    double maxCp_;
    
    // Base stats
    uint32_t str_;
    uint32_t dex_;
    uint32_t con_;
    uint32_t int_;
    uint32_t wit_;
    uint32_t men_;

public:
    Creature(uint32_t objectId, const std::string& name);
    virtual ~Creature() = default;

    // Getters
    const std::string& getName() const { return name_; }
    uint32_t getLevel() const { return level_; }
    uint64_t getExp() const { return exp_; }
    uint64_t getSp() const { return sp_; }
    
    double getCurrentHp() const { return currentHp_; }
    double getMaxHp() const { return maxHp_; }
    double getCurrentMp() const { return currentMp_; }
    double getMaxMp() const { return maxMp_; }
    double getCurrentCp() const { return currentCp_; }
    double getMaxCp() const { return maxCp_; }
    
    uint32_t getStr() const { return str_; }
    uint32_t getDex() const { return dex_; }
    uint32_t getCon() const { return con_; }
    uint32_t getInt() const { return int_; }
    uint32_t getWit() const { return wit_; }
    uint32_t getMen() const { return men_; }

    // Setters
    void setName(const std::string& name) { name_ = name; }
    void setLevel(uint32_t level) { level_ = level; }
    void setExp(uint64_t exp) { exp_ = exp; }
    void setSp(uint64_t sp) { sp_ = sp; }
    
    void setCurrentHp(double hp) { currentHp_ = hp; }
    void setMaxHp(double hp) { maxHp_ = hp; }
    void setCurrentMp(double mp) { currentMp_ = mp; }
    void setMaxMp(double mp) { maxMp_ = mp; }
    void setCurrentCp(double cp) { currentCp_ = cp; }
    void setMaxCp(double cp) { maxCp_ = cp; }
    
    void setStr(uint32_t str) { str_ = str; }
    void setDex(uint32_t dex) { dex_ = dex; }
    void setCon(uint32_t con) { con_ = con; }
    void setInt(uint32_t int_val) { int_ = int_val; }
    void setWit(uint32_t wit) { wit_ = wit; }
    void setMen(uint32_t men) { men_ = men; }
}; 