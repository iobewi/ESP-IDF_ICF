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

TEST_CASE("parse minimal", "[icf]")
{
    test_parse_minimal();
}
