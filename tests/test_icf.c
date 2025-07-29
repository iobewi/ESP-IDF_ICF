#include "unity.h"
#include "icf/icf.h"
#include <cjson/cJSON.h>
#include <sodium.h>
#include <string.h>
#include <stdlib.h>

static int fail_alloc;
void *test_malloc(size_t sz)
{
    if (fail_alloc) {
        fail_alloc = 0;
        return NULL;
    }
    return malloc(sz);
}

static int mock_verify_detached(const unsigned char *sig, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *pk)
{
    (void)m;
    (void)mlen;
    (void)pk;
    for (int i = 0; i < 64; ++i) {
        if (sig[i] != 0xAA) {
            return -1;
        }
    }
    return 0;
}

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

void test_parse_strict_valid_signature(void)
{
    uint8_t capsule[150];
    size_t pos = 0;
    capsule[pos++] = 0x01; capsule[pos++] = 3; memcpy(&capsule[pos], "abc", 3); pos += 3;
    size_t signed_len = pos;
    capsule[pos++] = 0xF2; capsule[pos++] = 0x20; size_t hash_pos = pos; pos += 32;
    capsule[pos++] = 0xF3; capsule[pos++] = 0x40; memset(&capsule[pos], 0xAA, 64); pos += 64;
    capsule[pos++] = 0xF4; capsule[pos++] = 0x08; for(int i=0;i<8;i++) capsule[pos++] = i;
    capsule[pos++] = 0xFF; capsule[pos++] = 0x00;
    uint8_t hash[32];
    crypto_hash_sha256(hash, capsule, signed_len);
    memcpy(&capsule[hash_pos], hash, 32);

    icf_capsule_t cap;
    uint8_t pk[32] = {0};
    icf_set_verify_func(mock_verify_detached);
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse_strict(capsule, pos, pk, &cap));
    icf_set_verify_func(NULL);
    icf_capsule_free(&cap);
}

void test_invalid_hash(void)
{
    uint8_t capsule[41];
    size_t pos = 0;
    capsule[pos++] = 0x01; capsule[pos++] = 0x03; memcpy(&capsule[pos], "abc", 3); pos += 3;
    capsule[pos++] = 0xF2; capsule[pos++] = 0x20; memset(&capsule[pos], 0, 32); pos += 32;
    capsule[pos++] = 0xFF; capsule[pos++] = 0x00;
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_CRC, icf_parse(capsule, pos, &cap));
}

void test_parse_complete_valid(void)
{
    uint8_t capsule[256];
    size_t pos = 0;
    capsule[pos++] = 0x01; capsule[pos++] = 3; memcpy(&capsule[pos], "url", 3); pos += 3;
    capsule[pos++] = 0x02; capsule[pos++] = 2; memcpy(&capsule[pos], "en", 2); pos += 2;
    capsule[pos++] = 0x03; capsule[pos++] = 5; memcpy(&capsule[pos], "title", 5); pos += 5;
    capsule[pos++] = 0x04; capsule[pos++] = 3; capsule[pos++] = 1; capsule[pos++] = 2; capsule[pos++] = 3;
    capsule[pos++] = 0x05; capsule[pos++] = 1; capsule[pos++] = 0x07;
    capsule[pos++] = 0x06; capsule[pos++] = 4; capsule[pos++] = 0x00; capsule[pos++] = 0x00; capsule[pos++] = 0x01; capsule[pos++] = 0x00;
    capsule[pos++] = 0xE0; capsule[pos++] = 1; capsule[pos++] = 0x02;
    capsule[pos++] = 0xE1; capsule[pos++] = 4; memcpy(&capsule[pos], "json", 4); pos += 4;
    size_t signed_len = pos;
    capsule[pos++] = 0xF2; capsule[pos++] = 0x20; size_t hash_pos = pos; pos += 32;
    capsule[pos++] = 0xF3; capsule[pos++] = 0x40; memset(&capsule[pos], 0, 64); pos += 64;
    capsule[pos++] = 0xF4; capsule[pos++] = 0x08; for(int i=0;i<8;i++) capsule[pos++] = i;
    capsule[pos++] = 0xFF; capsule[pos++] = 0x00;
    uint8_t hash[32];
    crypto_hash_sha256(hash, capsule, signed_len);
    memcpy(&capsule[hash_pos], hash, 32);

    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, pos, &cap));
    TEST_ASSERT_EQUAL_STRING("url", cap.url);
    TEST_ASSERT_EQUAL_STRING("en", cap.language);
    TEST_ASSERT_EQUAL_STRING("title", cap.title);
    TEST_ASSERT_EQUAL(1, cap.tag.cycle);
    TEST_ASSERT_EQUAL(2, cap.tag.subject);
    TEST_ASSERT_EQUAL(3, cap.tag.sub);
    TEST_ASSERT_EQUAL(0x07, cap.retention);
    TEST_ASSERT_EQUAL(256, cap.expires);
    TEST_ASSERT_EQUAL(ICF_BADGE_ADMIN, cap.badge_type);
    TEST_ASSERT_EQUAL(4, cap.payload_len);
    TEST_ASSERT_EQUAL(0, memcmp(cap.payload, "json", 4));
    TEST_ASSERT_EQUAL(1, cap.has_hash);
    TEST_ASSERT_EQUAL(1, cap.has_signature);
    TEST_ASSERT_EQUAL(1, cap.has_authority);
    icf_capsule_free(&cap);
}

void test_invalid_url_size(void)
{
    uint8_t capsule[205];
    capsule[0] = 0x01; capsule[1] = 201; memset(&capsule[2], 'a', 201); capsule[203] = 0xFF; capsule[204] = 0x00;
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, 205, &cap));
}

void test_invalid_language_size(void)
{
    const uint8_t capsule[] = {0x02,0x01,'e',0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_invalid_title_size(void)
{
    uint8_t capsule[70];
    capsule[0]=0x03; capsule[1]=65; memset(&capsule[2],'a',65); capsule[67]=0xFF; capsule[68]=0x00;
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, 69, &cap));
}

void test_invalid_tag_size(void)
{
    const uint8_t capsule[] = {0x04,0x02,1,2,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_invalid_retention_size(void)
{
    const uint8_t capsule[] = {0x05,0x02,1,2,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_invalid_expires_size(void)
{
    const uint8_t capsule[] = {0x06,0x03,0,0,0,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_invalid_badge_size(void)
{
    const uint8_t capsule[] = {0xE0,0x02,1,2,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_invalid_payload_nomem(void)
{
    const uint8_t capsule[] = {0xE1,0x04,'t','e','s','t',0xFF,0x00};
    icf_capsule_t cap;
    fail_alloc = 1;
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_json_payload_parse(void)
{
    const uint8_t capsule[] = {
        0xE1,0x07,'{','"','a','"',':','1','}',
        0xFF,0x00
    };
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    cJSON *json = icf_payload_to_json(&cap);
    assert(json != NULL);
    cJSON_Delete(json);
    icf_capsule_free(&cap);
}

void test_invalid_hash_length(void)
{
    uint8_t capsule[20];
    size_t pos = 0;
    capsule[pos++] = 0xF2; capsule[pos++] = 0x10; memset(&capsule[pos], 0, 16); pos += 16;
    capsule[pos++] = 0xFF; capsule[pos++] = 0x00;
    icf_capsule_t cap;
    esp_err_t ret = icf_parse(capsule, pos, &cap);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, ret);
}

void test_invalid_signature_length(void)
{
    const uint8_t capsule[] = {0xF3,0x01,0x00,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_invalid_authority_length(void)
{
    const uint8_t capsule[] = {0xF4,0x07,0,1,2,3,4,5,6,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

void test_invalid_end_length(void)
{
    const uint8_t capsule[] = {0xFF,0x01,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
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
    test_parse_strict_valid_signature();
    test_invalid_hash();
    test_parse_complete_valid();
    test_invalid_url_size();
    test_invalid_language_size();
    test_invalid_title_size();
    test_invalid_tag_size();
    test_invalid_retention_size();
    test_invalid_expires_size();
    test_invalid_badge_size();
    test_invalid_payload_nomem();
    test_json_payload_parse();
    test_invalid_hash_length();
    test_invalid_signature_length();
    test_invalid_authority_length();
    test_invalid_end_length();
    return UNITY_END();
}
