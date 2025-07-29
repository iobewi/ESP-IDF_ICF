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

void test_parse_strict_requires_fields(void)
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c',0xFF,0x00};
    icf_capsule_t cap;
    uint8_t pk[32] = {0};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, icf_parse_strict(capsule, sizeof(capsule), pk, &cap));
}

void test_parse_strict_invalid_signature(void)
{
    const uint8_t capsule[] = {
        0x01,0x03,'a','b','c',
        0xF2,0x20,
        /* 32 zero bytes */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0xF3,0x40,
        /* 64 zero bytes */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0xF4,0x08,0,1,2,3,4,5,6,7,
        0xFF,0x00
    };
    icf_capsule_t cap;
    uint8_t pk[32] = {0};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_CRC, icf_parse_strict(capsule, sizeof(capsule), pk, &cap));
}


int main(void)
{
    UNITY_BEGIN();
    test_parse_minimal();
    test_parse_no_end();
    test_parse_trailing_data();
    test_parse_trailing_after_end();
    test_parse_strict_requires_fields();
    test_parse_strict_invalid_signature();
    return UNITY_END();
}
