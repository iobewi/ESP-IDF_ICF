#include "unity.h"
#include "icf/icf.h"

void test_parse_minimal(void)
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c',0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_STRING("abc", cap.url);
    icf_capsule_free(&cap);
}

void test_parse_no_end(void)
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c'};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_STRING("abc", cap.url);
    icf_capsule_free(&cap);
}

void test_parse_trailing_data(void)
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c',0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_parse_trailing_after_end(void)
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c',0xFF,0x00,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("parse minimal", "[icf]")
{
    test_parse_minimal();
}

TEST_CASE("parse without end", "[icf]")
{
    test_parse_no_end();
}

TEST_CASE("parse trailing data", "[icf]")
{
    test_parse_trailing_data();
}

TEST_CASE("parse trailing after end", "[icf]")
{
    test_parse_trailing_after_end();
}
