#include "player.hpp"
#include <iostream>
#include <iomanip>

Player::Player(uint32_t objectId, const std::string& name, const std::string& accountName)
    : Creature(objectId, name)
    , accountName_(accountName)
    , sessionId_(0)
    , clanId_(0)
    , race_(0)
    , classId_(0)
    , sex_(0)
    , face_(0)
    , hairStyle_(0)
    , hairColor_(0)
    , karma_(0)
    , pvpKills_(0)
    , pkKills_(0)
    , fame_(0)
    , baseClassId_(0)
    , deleteTimer_(0)
    , enchantEffect_(0)
    , augmentationId_(0)
    , paperdollObjectIds_(16, 0)
    , paperdollItemIds_(16, 0)
    , clan_(nullptr)
    , party_(nullptr)
    , isOnline_(false)
    , isInDuel_(false)
    , isNoble_(false)
    , isHero_(false)
    , accessLevel_(0)
    , mountNpcId_(0)
    , mountLevel_(0)
    , mountObjectId_(0)
    , agathionId_(0)
    , vitalityPoints_(0)
    , pcCafePoints_(0)
    , onlineTime_(0)
    , lastAccess_(0)
    , createDate_(0)
    , lastRecomUpdate_(0)
    , recomHave_(0)
    , recomLeft_(0)
    , deathPenaltyBuffLevel_(0)
    , charges_(0)
    , powerGrade_(0)
    , pledgeClass_(0)
    , pledgeType_(0)
    , apprentice_(0)
    , sponsor_(0)
    , clanJoinExpiryTime_(0)
    , clanCreateExpiryTime_(0)
    , lvlJoinedAcademy_(0)
    , wantsPeace_(0)
    , partyRoom_(0)
    , siegeState_(0)
    , siegeSide_(0)
    , olympiadGameId_(0)
    , olympiadSide_(0)
    , olympiadBuffCount_(0)
    , duelId_(0)
    , duelState_(0)
    , pvpFlag_(0)
    , pvpFlagLasts_(0)
    , teleMode_(0)
    , partyDistributionType_(0)
    , privateStoreType_(0)
    , dietMode_(0)
    , tradeRefusal_(0)
    , exchangeRefusal_(0)
    , messageRefusal_(0)
    , silenceMode_(0)
    , inventoryBlockingStatus_(0)
    , expertiseArmorPenalty_(0)
    , expertiseWeaponPenalty_(0)
    , expertisePenaltyBonus_(0)
    , weightPenalty_(0)
    , curWeightPenalty_(0)
    , inventoryLimit_(0)
    , warehouseLimit_(0)
    , privateSellStoreLimit_(0)
    , privateBuyStoreLimit_(0)
    , dwarfRecipeLimit_(0)
    , commonRecipeLimit_(0)
    , questInventoryLimit_(0)
    , bookmarkslot_(0)
    , language_(0)
    , faction_(0)
    , newbie_(0)
    , nobless_(0)
    , isIn7sDungeon_(0)
    , clanPrivileges_(0)
    , subpledge_(0)
    , titleColor_(0)
    , title_(0)
    , cancraft_(0)
    , onlinetime_(0)
    , isin7sdungeon_(0)
    , last_recom_date_(0)
    , rec_have_(0)
    , rec_left_(0)
    , death_penalty_level_(0)
    , vitality_points_(0)
    , pccafe_points_(0)
{
}

void Player::setPaperdollObjectId(size_t slot, uint32_t objectId)
{
    if (slot < paperdollObjectIds_.size()) {
        paperdollObjectIds_[slot] = objectId;
    }
}

void Player::setPaperdollItemId(size_t slot, uint32_t itemId)
{
    if (slot < paperdollItemIds_.size()) {
        paperdollItemIds_[slot] = itemId;
    }
}

void Player::dump() const
{
    std::cout << "\n=== Player Dump ===" << std::endl;
    std::cout << "Object ID: " << getObjectId() << std::endl;
    std::cout << "Name: " << getName() << std::endl;
    std::cout << "Account: " << accountName_ << std::endl;
    std::cout << "Session ID: " << sessionId_ << std::endl;
    std::cout << "Position: (" << getX() << ", " << getY() << ", " << getZ() << ") heading=" << getHeading() << std::endl;
    
    std::cout << "\n--- Stats ---" << std::endl;
    std::cout << "Level: " << getLevel() << std::endl;
    std::cout << "EXP: " << getExp() << std::endl;
    std::cout << "SP: " << getSp() << std::endl;
    std::cout << "HP: " << getCurrentHp() << "/" << getMaxHp() << std::endl;
    std::cout << "MP: " << getCurrentMp() << "/" << getMaxMp() << std::endl;
    std::cout << "CP: " << getCurrentCp() << "/" << getMaxCp() << std::endl;
    
    std::cout << "\n--- Base Stats ---" << std::endl;
    std::cout << "STR: " << getStr() << " DEX: " << getDex() << " CON: " << getCon() << std::endl;
    std::cout << "INT: " << getInt() << " WIT: " << getWit() << " MEN: " << getMen() << std::endl;
    
    std::cout << "\n--- Character Info ---" << std::endl;
    std::cout << "Race: " << race_ << " (0=human, 1=elf, 2=dark_elf, 3=orc, 4=dwarf)" << std::endl;
    std::cout << "Class ID: " << classId_ << std::endl;
    std::cout << "Base Class ID: " << baseClassId_ << std::endl;
    std::cout << "Sex: " << sex_ << " (0=male, 1=female)" << std::endl;
    std::cout << "Face: " << face_ << std::endl;
    std::cout << "Hair Style: " << hairStyle_ << std::endl;
    std::cout << "Hair Color: " << hairColor_ << std::endl;
    
    std::cout << "\n--- Status ---" << std::endl;
    std::cout << "Karma: " << karma_ << std::endl;
    std::cout << "PvP Kills: " << pvpKills_ << std::endl;
    std::cout << "PK Kills: " << pkKills_ << std::endl;
    std::cout << "Fame: " << fame_ << std::endl;
    std::cout << "Clan ID: " << clanId_ << std::endl;
    std::cout << "Delete Timer: " << deleteTimer_ << std::endl;
    std::cout << "Enchant Effect: " << enchantEffect_ << std::endl;
    std::cout << "Augmentation ID: " << augmentationId_ << std::endl;
    
    std::cout << "\n--- Equipment (Paperdoll) ---" << std::endl;
    for (size_t i = 0; i < paperdollObjectIds_.size(); ++i) {
        if (paperdollObjectIds_[i] != 0 || paperdollItemIds_[i] != 0) {
            std::cout << "Slot " << i << ": ObjectID=" << paperdollObjectIds_[i] 
                      << " ItemID=" << paperdollItemIds_[i] << std::endl;
        }
    }
    
    std::cout << "\n--- Stubbed Properties (All return defaults) ---" << std::endl;
    std::cout << "Skills count: " << skills_.size() << std::endl;
    std::cout << "Clan: " << (clan_ ? "exists" : "nullptr") << std::endl;
    std::cout << "Party: " << (party_ ? "exists" : "nullptr") << std::endl;
    std::cout << "Inventory count: " << inventory_.size() << std::endl;
    std::cout << "Online: " << (isOnline_ ? "true" : "false") << std::endl;
    std::cout << "In Duel: " << (isInDuel_ ? "true" : "false") << std::endl;
    std::cout << "Noble: " << (isNoble_ ? "true" : "false") << std::endl;
    std::cout << "Hero: " << (isHero_ ? "true" : "false") << std::endl;
    std::cout << "Access Level: " << accessLevel_ << std::endl;
    std::cout << "Mount NPC ID: " << mountNpcId_ << std::endl;
    std::cout << "Mount Level: " << mountLevel_ << std::endl;
    std::cout << "Mount Object ID: " << mountObjectId_ << std::endl;
    std::cout << "Agathion ID: " << agathionId_ << std::endl;
    std::cout << "Vitality Points: " << vitalityPoints_ << std::endl;
    std::cout << "PC Cafe Points: " << pcCafePoints_ << std::endl;
    std::cout << "Online Time: " << onlineTime_ << std::endl;
    std::cout << "Last Access: " << lastAccess_ << std::endl;
    std::cout << "Create Date: " << createDate_ << std::endl;
    std::cout << "Last Recom Update: " << lastRecomUpdate_ << std::endl;
    std::cout << "Recom Have: " << recomHave_ << std::endl;
    std::cout << "Recom Left: " << recomLeft_ << std::endl;
    std::cout << "Death Penalty Buff Level: " << deathPenaltyBuffLevel_ << std::endl;
    std::cout << "Charges: " << charges_ << std::endl;
    std::cout << "Power Grade: " << powerGrade_ << std::endl;
    std::cout << "Pledge Class: " << pledgeClass_ << std::endl;
    std::cout << "Pledge Type: " << pledgeType_ << std::endl;
    std::cout << "Apprentice: " << apprentice_ << std::endl;
    std::cout << "Sponsor: " << sponsor_ << std::endl;
    std::cout << "Clan Join Expiry Time: " << clanJoinExpiryTime_ << std::endl;
    std::cout << "Clan Create Expiry Time: " << clanCreateExpiryTime_ << std::endl;
    std::cout << "Level Joined Academy: " << lvlJoinedAcademy_ << std::endl;
    std::cout << "Wants Peace: " << wantsPeace_ << std::endl;
    std::cout << "Party Room: " << partyRoom_ << std::endl;
    std::cout << "Siege State: " << siegeState_ << std::endl;
    std::cout << "Siege Side: " << siegeSide_ << std::endl;
    std::cout << "Olympiad Game ID: " << olympiadGameId_ << std::endl;
    std::cout << "Olympiad Side: " << olympiadSide_ << std::endl;
    std::cout << "Olympiad Buff Count: " << olympiadBuffCount_ << std::endl;
    std::cout << "Duel ID: " << duelId_ << std::endl;
    std::cout << "Duel State: " << duelState_ << std::endl;
    std::cout << "PvP Flag: " << pvpFlag_ << std::endl;
    std::cout << "PvP Flag Lasts: " << pvpFlagLasts_ << std::endl;
    std::cout << "Tele Mode: " << teleMode_ << std::endl;
    std::cout << "Party Distribution Type: " << partyDistributionType_ << std::endl;
    std::cout << "Private Store Type: " << privateStoreType_ << std::endl;
    std::cout << "Diet Mode: " << dietMode_ << std::endl;
    std::cout << "Trade Refusal: " << tradeRefusal_ << std::endl;
    std::cout << "Exchange Refusal: " << exchangeRefusal_ << std::endl;
    std::cout << "Message Refusal: " << messageRefusal_ << std::endl;
    std::cout << "Silence Mode: " << silenceMode_ << std::endl;
    std::cout << "Inventory Blocking Status: " << inventoryBlockingStatus_ << std::endl;
    std::cout << "Expertise Armor Penalty: " << expertiseArmorPenalty_ << std::endl;
    std::cout << "Expertise Weapon Penalty: " << expertiseWeaponPenalty_ << std::endl;
    std::cout << "Expertise Penalty Bonus: " << expertisePenaltyBonus_ << std::endl;
    std::cout << "Weight Penalty: " << weightPenalty_ << std::endl;
    std::cout << "Current Weight Penalty: " << curWeightPenalty_ << std::endl;
    std::cout << "Inventory Limit: " << inventoryLimit_ << std::endl;
    std::cout << "Warehouse Limit: " << warehouseLimit_ << std::endl;
    std::cout << "Private Sell Store Limit: " << privateSellStoreLimit_ << std::endl;
    std::cout << "Private Buy Store Limit: " << privateBuyStoreLimit_ << std::endl;
    std::cout << "Dwarf Recipe Limit: " << dwarfRecipeLimit_ << std::endl;
    std::cout << "Common Recipe Limit: " << commonRecipeLimit_ << std::endl;
    std::cout << "Quest Inventory Limit: " << questInventoryLimit_ << std::endl;
    std::cout << "Bookmark Slot: " << bookmarkslot_ << std::endl;
    std::cout << "Language: " << language_ << std::endl;
    std::cout << "Faction: " << faction_ << std::endl;
    std::cout << "Newbie: " << newbie_ << std::endl;
    std::cout << "Nobless: " << nobless_ << std::endl;
    std::cout << "Is In 7s Dungeon: " << isIn7sDungeon_ << std::endl;
    std::cout << "Clan Privileges: " << clanPrivileges_ << std::endl;
    std::cout << "Subpledge: " << subpledge_ << std::endl;
    std::cout << "Title Color: " << titleColor_ << std::endl;
    std::cout << "Title: " << title_ << std::endl;
    std::cout << "Can Craft: " << cancraft_ << std::endl;
    std::cout << "Online Time: " << onlinetime_ << std::endl;
    std::cout << "Is In 7s Dungeon: " << isin7sdungeon_ << std::endl;
    std::cout << "Last Recom Date: " << last_recom_date_ << std::endl;
    std::cout << "Rec Have: " << rec_have_ << std::endl;
    std::cout << "Rec Left: " << rec_left_ << std::endl;
    std::cout << "Death Penalty Level: " << death_penalty_level_ << std::endl;
    std::cout << "Vitality Points: " << vitality_points_ << std::endl;
    std::cout << "PC Cafe Points: " << pccafe_points_ << std::endl;
    
    std::cout << "=== End Player Dump ===\n" << std::endl;
} 