#include <unity.h>
#include "icf/icf.h"
#include <cJSON.h>
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

static void fill_capsule(icf_capsule_t *cap) {
    memset(cap, 0, sizeof(*cap));
}

TEST_CASE("icf_parse minimal", "[icf]")
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c',0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_STRING("abc", cap.url);
    icf_capsule_free(&cap);
}

TEST_CASE("icf_parse no end", "[icf]")
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c'};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_STRING("abc", cap.url);
    icf_capsule_free(&cap);
}

TEST_CASE("icf_parse trailing data", "[icf]")
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c',0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse trailing after end", "[icf]")
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c',0xFF,0x00,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse_strict requires fields", "[icf]")
{
    const uint8_t capsule[] = {0x01,0x03,'a','b','c',0xFF,0x00};
    icf_capsule_t cap;
    uint8_t pk[32] = {0};
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_STATE, icf_parse_strict(capsule, sizeof(capsule), pk, &cap));
}

TEST_CASE("icf_parse_strict invalid signature", "[icf]")
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

TEST_CASE("icf_parse_strict valid signature", "[icf]")
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

TEST_CASE("icf_parse invalid hash", "[icf]")
{
    uint8_t capsule[41];
    size_t pos = 0;
    capsule[pos++] = 0x01; capsule[pos++] = 0x03; memcpy(&capsule[pos], "abc", 3); pos += 3;
    capsule[pos++] = 0xF2; capsule[pos++] = 0x20; memset(&capsule[pos], 0, 32); pos += 32;
    capsule[pos++] = 0xFF; capsule[pos++] = 0x00;
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_CRC, icf_parse(capsule, pos, &cap));
}

TEST_CASE("icf_parse complete valid", "[icf]")
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

TEST_CASE("icf_parse invalid url size", "[icf]")
{
    uint8_t capsule[205];
    capsule[0] = 0x01; capsule[1] = 201; memset(&capsule[2], 'a', 201); capsule[203] = 0xFF; capsule[204] = 0x00;
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, 205, &cap));
}

TEST_CASE("icf_parse invalid language size", "[icf]")
{
    const uint8_t capsule[] = {0x02,0x01,'e',0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse invalid title size", "[icf]")
{
    uint8_t capsule[70];
    capsule[0]=0x03; capsule[1]=65; memset(&capsule[2],'a',65); capsule[67]=0xFF; capsule[68]=0x00;
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, 69, &cap));
}

TEST_CASE("icf_parse invalid tag size", "[icf]")
{
    const uint8_t capsule[] = {0x04,0x02,1,2,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse invalid retention size", "[icf]")
{
    const uint8_t capsule[] = {0x05,0x02,1,2,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse invalid expires size", "[icf]")
{
    const uint8_t capsule[] = {0x06,0x03,0,0,0,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse invalid badge size", "[icf]")
{
    const uint8_t capsule[] = {0xE0,0x02,1,2,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse invalid payload nomem", "[icf]")
{
    const uint8_t capsule[] = {0xE1,0x04,'t','e','s','t',0xFF,0x00};
    icf_capsule_t cap;
    fail_alloc = 1;
    TEST_ASSERT_EQUAL(ESP_ERR_NO_MEM, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_payload json parse", "[icf]")
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

TEST_CASE("icf_parse invalid hash length", "[icf]")
{
    uint8_t capsule[20];
    size_t pos = 0;
    capsule[pos++] = 0xF2; capsule[pos++] = 0x10; memset(&capsule[pos], 0, 16); pos += 16;
    capsule[pos++] = 0xFF; capsule[pos++] = 0x00;
    icf_capsule_t cap;
    esp_err_t ret = icf_parse(capsule, pos, &cap);
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, ret);
}

TEST_CASE("icf_parse invalid signature length", "[icf]")
{
    const uint8_t capsule[] = {0xF3,0x01,0x00,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse invalid authority length", "[icf]")
{
    const uint8_t capsule[] = {0xF4,0x07,0,1,2,3,4,5,6,0xFF,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("icf_parse invalid end length", "[icf]")
{
    const uint8_t capsule[] = {0xFF,0x01,0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("TLV: Langue ISO 639-1 correcte", "[icf]") {
    const uint8_t capsule[] = {0x02, 0x02, 'f', 'r', 0xFF, 0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_STRING("fr", cap.language);
}

TEST_CASE("TLV: Titre UTF-8", "[icf]") {
    const uint8_t capsule[] = {0x03, 0x05, 'H', 'e', 'l', 'l', 'o', 0xFF, 0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    // Pas d'assert spécifique car cap.title peut être absent de la struct
}

TEST_CASE("TLV: Tag pédagogique complet", "[icf]") {
    const uint8_t capsule[] = {0x04, 0x03, 0x01, 0x02, 0x11, 0xFF, 0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_UINT8(0x01, cap.tag.cycle);
    TEST_ASSERT_EQUAL_UINT8(0x02, cap.tag.subject);
    TEST_ASSERT_EQUAL_UINT8(0x11, cap.tag.sub);
}

TEST_CASE("TLV: Rétention 0 et 255", "[icf]") {
    const uint8_t capsule1[] = {0x05, 0x01, 0x00, 0xFF, 0x00};
    const uint8_t capsule2[] = {0x05, 0x01, 0xFF, 0xFF, 0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule1, sizeof(capsule1), &cap));
    TEST_ASSERT_EQUAL_UINT8(0x00, cap.retention);
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule2, sizeof(capsule2), &cap));
    TEST_ASSERT_EQUAL_UINT8(0xFF, cap.retention);
}

TEST_CASE("TLV: Expiration big-endian", "[icf]") {
    const uint8_t capsule[] = {0x06, 0x04, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_UINT32(1, cap.expires);
}

TEST_CASE("TLV: Type de badge", "[icf]") {
    const uint8_t capsule[] = {0xE0, 0x01, 0x02, 0xFF, 0x00};  // badge admin
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_UINT8(0x02, cap.badge_type);
}

TEST_CASE("TLV: Payload JSON clair", "[icf]") {
    const uint8_t json[] = "{"volume":42}";
    uint8_t capsule[64] = {0xE1, sizeof(json) - 1};
    memcpy(&capsule[2], json, sizeof(json) - 1);
    capsule[2 + sizeof(json) - 1] = 0xFF;
    capsule[3 + sizeof(json) - 1] = 0x00;
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, 4 + sizeof(json) - 1, &cap));
}

TEST_CASE("TLV: Authority ID parsing", "[icf]") {
    const uint8_t capsule[] = {0xF4, 0x08, 1,2,3,4,5,6,7,8, 0xFF, 0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_TRUE(cap.has_authority);
    TEST_ASSERT_EQUAL_UINT8(1, cap.authority_id[0]);
    TEST_ASSERT_EQUAL_UINT8(8, cap.authority_id[7]);
}

TEST_CASE("TLV: Mauvaise taille - langue", "[icf]") {
    const uint8_t capsule[] = {0x02, 0x01, 'f', 0xFF, 0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_ERR_INVALID_SIZE, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("TLV: TLV inconnu ignoré", "[icf]") {
    const uint8_t capsule[] = {0x7A, 0x03, 1,2,3, 0x01, 0x03, 'a','b','c', 0xFF, 0x00};
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
}

TEST_CASE("TLV: Répétition du champ URL", "[icf]") {
    const uint8_t capsule[] = {
        0x01, 0x03, 'a','b','c',
        0x01, 0x03, 'x','y','z',
        0xFF, 0x00
    };
    icf_capsule_t cap;
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse(capsule, sizeof(capsule), &cap));
    TEST_ASSERT_EQUAL_STRING("xyz", cap.url); // Doit écraser le précédent
}

TEST_CASE("Capsule complète signée avec hash et authority ID", "[icf]") {
    const uint8_t capsule[] = {
        1, 3, 97, 98, 99, 242, 32, 161, 139, 177, 204, 7, 128, 172, 155, 138, 48, 94, 191, 225, 38, 84, 102, 141, 2, 128, 242, 95, 57, 184, 158, 99, 98, 232, 155, 247, 110, 50, 4, 243, 64, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 170, 244, 8, 1, 2, 3, 4, 5, 6, 7, 8, 255, 0
    };
    icf_capsule_t cap;
    icf_set_verify_func(mock_verify_detached);  // active le mock de signature
    TEST_ASSERT_EQUAL(ESP_OK, icf_parse_strict(capsule, sizeof(capsule), (const uint8_t*)"", &cap));
    TEST_ASSERT_EQUAL_STRING("abc", cap.url);
    TEST_ASSERT_TRUE(cap.has_signature);
    TEST_ASSERT_TRUE(cap.has_authority);
}

void app_main(void)
{
    UNITY_BEGIN();
    UNITY_END();
}