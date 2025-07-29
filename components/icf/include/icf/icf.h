#ifndef ICF_H
#define ICF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** TLV types */
typedef enum {
    ICF_TLV_URL         = 0x01,
    ICF_TLV_LANGUAGE    = 0x02,
    ICF_TLV_TITLE       = 0x03,
    ICF_TLV_TAG         = 0x04,
    ICF_TLV_RETENTION   = 0x05,
    ICF_TLV_EXPIRES     = 0x06,
    ICF_TLV_BADGE_TYPE  = 0xE0,
    ICF_TLV_SYS_PAYLOAD = 0xE1,
    ICF_TLV_HASH        = 0xF2,
    ICF_TLV_SIGNATURE   = 0xF3,
    ICF_TLV_AUTHORITY_ID= 0xF4,
    ICF_TLV_END         = 0xFF
} icf_tlv_type_t;

/** Badge types */
typedef enum {
    ICF_BADGE_RESOURCE      = 0x00,
    ICF_BADGE_CONFIGURATION = 0x01,
    ICF_BADGE_ADMIN         = 0x02
} icf_badge_type_t;

/** Tag pedagogique */
typedef struct {
    uint8_t cycle;
    uint8_t subject;
    uint8_t sub;
} icf_tag_t;

/** Capsule structure */
typedef struct {
    icf_badge_type_t badge_type;
    char url[201];
    char language[3];
    char title[65];
    icf_tag_t tag;
    uint8_t retention;
    uint32_t expires;
    uint8_t *payload;      /**< JSON payload if present */
    size_t payload_len;
    uint8_t hash[32];
    uint8_t signature[64];
    uint8_t authority_id[8];
    bool has_hash;
    bool has_signature;
    bool has_authority;
} icf_capsule_t;

esp_err_t icf_parse(const uint8_t *buffer, size_t len, icf_capsule_t *capsule);
bool icf_verify(const icf_capsule_t *capsule, const uint8_t pubkey[32]);
void icf_capsule_print(const icf_capsule_t *capsule);
void icf_capsule_free(icf_capsule_t *capsule);

#ifdef __cplusplus
}
#endif

#endif // ICF_H
