#include <iostream>
#include <string>

#include <blowfish/blowfish.h>

void test_blowfish()
{
    // Initialize Blowfish with a key
    std::string key = "MySecretKey123";
    Blowfish bf(key);

    // Test data
    uint32_t left = 0x12345678;
    uint32_t right = 0x90ABCDEF;

    // Make a copy for verification
    uint32_t orig_left = left;
    uint32_t orig_right = right;

    // Encrypt
    bf.encrypt(left, right);

    // Decrypt
    bf.decrypt(left, right);

    // Verify
    if (left == orig_left && right == orig_right)
    {
        std::cout << "Blowfish test passed!" << std::endl;
    }
    else
    {
        std::cout << "Blowfish test failed!" << std::endl;
    }
}

int main()
{
    test_blowfish();

    return 0;
}
