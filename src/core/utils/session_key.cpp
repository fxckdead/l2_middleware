#include "session_key.hpp"
#include <iostream>

// Generate random session key (matches Rust SessionKey::new())
SessionKey SessionKey::generate()
{
    static std::random_device rd;
    static std::mt19937 gen(rd());

    return SessionKey{
        static_cast<int32_t>(gen()),
        static_cast<int32_t>(gen()),
        static_cast<int32_t>(gen()),
        static_cast<int32_t>(gen())};
}

// Check login server session (matches Rust check_session)
bool SessionKey::check_session(int32_t s_key_1, int32_t s_key_2) const
{
    return s_key_1 == login_ok1 && s_key_2 == login_ok2;
}

// Compare sessions between servers (matches Rust equals)
bool SessionKey::equals(const SessionKey &other, bool show_license) const
{
    bool is_play_ok = play_ok1 == other.play_ok1 && play_ok2 == other.play_ok2;

    if (show_license)
    {
        return is_play_ok && login_ok1 == other.login_ok1 && login_ok2 == other.login_ok2;
    }

    return is_play_ok;
}

// Get play session ID (matches Rust get_play_session_id)
int32_t SessionKey::get_play_session_id() const
{
    return play_ok1;
}

// Equality operator
bool SessionKey::operator==(const SessionKey &other) const
{
    return play_ok1 == other.play_ok1 &&
           play_ok2 == other.play_ok2 &&
           login_ok1 == other.login_ok1 &&
           login_ok2 == other.login_ok2;
}

bool SessionKey::operator!=(const SessionKey &other) const
{
    return !(*this == other);
}

// Test function with Rust compatibility test vectors
void SessionKey::runTests()
{
    std::cout << "\n=== Testing Session Key Management (Rust Compatibility) ===" << std::endl;

    bool all_passed = true;

    // Test 1: Session key not equals (from Rust test_session_key_not_equals)
    std::cout << "Test 1: Session key not equals" << std::endl;
    {
        SessionKey session_key = SessionKey::generate();
        SessionKey other_session = SessionKey::generate();

        // Two different generated sessions should not be equal
        bool test1a = !session_key.equals(other_session, false);
        bool test1b = !session_key.equals(other_session, true);

        if (test1a && test1b)
        {
            std::cout << "  ✅ Test 1 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 1 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Test 2: Session key equals (from Rust test_session_key_equals)
    std::cout << "\nTest 2: Session key equals" << std::endl;
    {
        SessionKey session_key = SessionKey::generate();
        SessionKey other = session_key; // Copy (equivalent to Rust clone())

        // Copied session should be equal
        bool test2a = session_key.equals(other, false);
        bool test2b = session_key.equals(other, true);

        if (test2a && test2b)
        {
            std::cout << "  ✅ Test 2 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 2 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Test 3: Session key check session (from Rust test_session_key_check_session)
    std::cout << "\nTest 3: Session key check session" << std::endl;
    {
        SessionKey session_key = SessionKey::generate();

        // Should validate correctly when using the same login keys
        bool test3 = session_key.check_session(session_key.login_ok1, session_key.login_ok2);

        if (test3)
        {
            std::cout << "  ✅ Test 3 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 3 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Test 4: Additional functionality tests
    std::cout << "\nTest 4: Additional functionality" << std::endl;
    {
        // Test explicit constructor and get_play_session_id
        SessionKey session_key(100, 200, 300, 400);

        bool test4a = session_key.get_play_session_id() == 100;
        bool test4b = session_key.check_session(300, 400);  // Should pass
        bool test4c = !session_key.check_session(999, 888); // Should fail

        // Test equals with specific values
        SessionKey same_session(100, 200, 300, 400);
        SessionKey different_play(999, 200, 300, 400);
        SessionKey different_login(100, 200, 999, 400);

        bool test4d = session_key.equals(same_session, true);
        bool test4e = !session_key.equals(different_play, false);
        bool test4f = session_key.equals(different_login, false); // Only play keys matter
        bool test4g = !session_key.equals(different_login, true); // All keys matter

        if (test4a && test4b && test4c && test4d && test4e && test4f && test4g)
        {
            std::cout << "  ✅ Test 4 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 4 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Test 5: Operator overloads
    std::cout << "\nTest 5: Operator overloads" << std::endl;
    {
        SessionKey session1(1, 2, 3, 4);
        SessionKey session2(1, 2, 3, 4);
        SessionKey session3(5, 6, 7, 8);

        bool test5a = session1 == session2;
        bool test5b = session1 != session3;
        bool test5c = !(session1 == session3);

        if (test5a && test5b && test5c)
        {
            std::cout << "  ✅ Test 5 PASSED!" << std::endl;
        }
        else
        {
            std::cout << "  ❌ Test 5 FAILED!" << std::endl;
            all_passed = false;
        }
    }

    // Overall result
    if (all_passed)
    {
        std::cout << "\n🎉 ALL Session Key tests PASSED!" << std::endl;
    }
    else
    {
        std::cout << "\n⚠️ Some Session Key tests FAILED!" << std::endl;
    }
    std::cout << std::endl;
}