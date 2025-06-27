#pragma once

#include <string>
#include <cstdint>
#include <openssl/blowfish.h>

class Blowfish
{
private:
    BF_KEY m_key;

public:
    Blowfish() {}
    explicit Blowfish(const std::string &key);
    Blowfish(const Blowfish &) = delete;

    void initialize(const std::string &key);
    void encrypt(uint32_t &xl, uint32_t &xr);
    void decrypt(uint32_t &xl, uint32_t &xr);
};