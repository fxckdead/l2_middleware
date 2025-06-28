#include "packet_tests.cpp"
#include "responses/login_ok_response_test.cpp"
#include "responses/init_packet_test.cpp"
#include "responses/auth_gg_response_test.cpp"
#include "requests/request_auth_gg_test.cpp"
#include "requests/auth_login_packet_test.cpp"
#include "packet_factory_test.cpp"

void run_all_login_tests()
{
    std::cout << "\n"
              << std::string(60, '=') << std::endl;
    std::cout << "        L2 MIDDLEWARES - LOGIN MODULE TEST SUITE" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    // Run response packet tests
    test_login_ok_response();
    test_init_packet_unit();
    test_auth_gg_response();

    // Run request packet tests
    test_request_auth_gg();
    test_auth_login_packet();

    // Run demo and debug functions
    demo_l2_auth_flow();
    debug_rust_test_data();

    // Run factory tests
    test_packet_factory();

    // Run packet integration tests
    test_integration_with_crypto();
    test_full_auth_flow();
    test_packet_serialization_roundtrip();

    std::cout << std::string(60, '=') << std::endl;
    std::cout << "        ALL LOGIN MODULE TESTS COMPLETED" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}