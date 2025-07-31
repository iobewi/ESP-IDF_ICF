#ifndef ICF_H
#define ICF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <cJSON.h>
#include "esp_err.h"

/** Read a 32-bit unsigned integer encoded in big-endian order */
#define READ_U32_BE(ptr) \
    (((uint32_t)((const uint8_t *)(ptr))[0] << 24) | \
     ((uint32_t)((const uint8_t *)(ptr))[1] << 16) | \
     ((uint32_t)((const uint8_t *)(ptr))[2] << 8)  | \
     ((uint32_t)((const uint8_t *)(ptr))[3]))

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

/**
 * @brief Cycle pedagogique selon SPEC-ICF
 */
typedef enum {
    ICF_CYCLE_UNDEFINED    = 0x00,
    ICF_CYCLE_1_MATERNELLE = 0x01,
    ICF_CYCLE_2_CPC2       = 0x02,
    ICF_CYCLE_3_CM16E      = 0x03,
    ICF_CYCLE_4_543E       = 0x04,
    ICF_CYCLE_LOCAL        = 0xFE,
    ICF_CYCLE_RESERVED     = 0xFF,
} icf_cycle_t;

/**
 * @brief Matière pédagogique selon SPEC-ICF
 */
typedef enum {
    ICF_SUBJECT_UNDEFINED = 0x00,
    ICF_SUBJECT_READING   = 0x01,
    ICF_SUBJECT_SCIENCE   = 0x02,
    ICF_SUBJECT_MUSIC     = 0x03,
    ICF_SUBJECT_FOREIGN   = 0x04,
    ICF_SUBJECT_PROJECT   = 0x05,
    ICF_SUBJECT_MATH      = 0x06,
    ICF_SUBJECT_CIVIC     = 0x07,
    ICF_SUBJECT_LOCAL     = 0xFE,
    ICF_SUBJECT_RESERVED  = 0xFF,
} icf_subject_t;

/** Tag pedagogique */
typedef struct {
    icf_cycle_t cycle;
    icf_subject_t subject;
    uint8_t sub;  /**< Champ libre, non normalisé */
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

/** Lookup function returning the public key for an authority. */
typedef const uint8_t *(*icf_pubkey_lookup_func_t)(const uint8_t authority_id[8]);

/**
 * Parse a capsule and optionally verify it.
 *
 * @param buffer   Raw capsule data
 * @param len      Length of the buffer
 * @param capsule  Output structure for parsed fields
 * @param strict   Require signature and authority ID when true
 * @param key_lookup  Callback to obtain the public key based on authority_id.
 *                    Can be NULL if no verification is needed.
 */
esp_err_t icf_parse(const uint8_t *buffer, size_t len, icf_capsule_t *capsule,
                    bool strict, icf_pubkey_lookup_func_t key_lookup);
bool icf_verify(const icf_capsule_t *capsule, const uint8_t pubkey[32]);
void icf_capsule_print(const icf_capsule_t *capsule);
void icf_capsule_free(icf_capsule_t *capsule);

const char *icf_cycle_to_string(icf_cycle_t cycle);
const char *icf_subject_to_string(icf_subject_t subject);
const char *icf_tag_to_string(const icf_tag_t *tag);

typedef int (*icf_verify_func_t)(const unsigned char *sig,
                                 const unsigned char *m,
                                 unsigned long long mlen,
                                 const unsigned char *pk);

void icf_set_verify_func(icf_verify_func_t func);

/**
 * @brief Parse the JSON system payload into a cJSON object.
 *
 * The caller takes ownership of the returned object and must free it
 * using cJSON_Delete(). NULL is returned if the capsule has no payload
 * or if parsing fails.
 */
cJSON *icf_payload_to_json(const icf_capsule_t *capsule);

#ifdef __cplusplus
}
#endif

#endif // ICF_H
