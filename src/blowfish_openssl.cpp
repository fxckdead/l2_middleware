#include "blowfish_openssl.hpp"

Blowfish::Blowfish(const std::string &key)
{
    initialize(key);
}

void Blowfish::initialize(const std::string &key)
{
    BF_set_key(&m_key, static_cast<int>(key.length()),
               reinterpret_cast<const unsigned char *>(key.c_str()));
}

void Blowfish::encrypt(uint32_t &xl, uint32_t &xr)
{
    // OpenSSL's BF_encrypt expects BF_LONG array
    BF_LONG data[2];
    data[0] = static_cast<BF_LONG>(xl);
    data[1] = static_cast<BF_LONG>(xr);

    BF_encrypt(data, &m_key);

    xl = static_cast<uint32_t>(data[0]);
    xr = static_cast<uint32_t>(data[1]);
}

void Blowfish::decrypt(uint32_t &xl, uint32_t &xr)
{
    // OpenSSL's BF_decrypt expects BF_LONG array
    BF_LONG data[2];
    data[0] = static_cast<BF_LONG>(xl);
    data[1] = static_cast<BF_LONG>(xr);

    BF_decrypt(data, &m_key);

    xl = static_cast<uint32_t>(data[0]);
    xr = static_cast<uint32_t>(data[1]);
}