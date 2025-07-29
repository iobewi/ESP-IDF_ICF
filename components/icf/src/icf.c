#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "icf/icf.h"

static esp_err_t parse_tlv_url(icf_capsule_t *capsule,
                               const uint8_t *value, uint8_t len)
{
    if (len >= sizeof(capsule->url)) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(capsule->url, value, len);
    capsule->url[len] = '\0';
    return ESP_OK;
}

static esp_err_t parse_tlv_lang(icf_capsule_t *capsule,
                                const uint8_t *value, uint8_t len)
{
    if (len != 2) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(capsule->language, value, 2);
    capsule->language[2] = '\0';
    return ESP_OK;
}

static esp_err_t parse_tlv_signature(icf_capsule_t *capsule,
                                     const uint8_t *value, uint8_t len)
{
    if (len != 64) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(capsule->signature, value, 64);
    capsule->has_signature = true;
    return ESP_OK;
}

esp_err_t icf_parse(const uint8_t *buffer, size_t len, icf_capsule_t *capsule)
{
    if (!buffer || !capsule) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(capsule, 0, sizeof(*capsule));
    capsule->badge_type = ICF_BADGE_RESOURCE; // default

    size_t pos = 0;
    size_t signed_len = 0;

    bool got_end = false;
    esp_err_t err;

    while (pos + 2 <= len) {
        uint8_t type = buffer[pos++];
        uint8_t tlv_len = buffer[pos++];
        if (pos + tlv_len > len) {
            return ESP_ERR_INVALID_SIZE;
        }

        const uint8_t *value = &buffer[pos];

        switch (type) {
        case ICF_TLV_URL:
            err = parse_tlv_url(capsule, value, tlv_len);
            if (err != ESP_OK) return err;
            break;
        case ICF_TLV_LANGUAGE:
            err = parse_tlv_lang(capsule, value, tlv_len);
            if (err != ESP_OK) return err;
            break;
        case ICF_TLV_TITLE:
            if (tlv_len >= sizeof(capsule->title)) return ESP_ERR_INVALID_SIZE;
            memcpy(capsule->title, value, tlv_len);
            capsule->title[tlv_len] = '\0';
            break;
        case ICF_TLV_TAG:
            if (tlv_len != 3) return ESP_ERR_INVALID_SIZE;
            capsule->tag.cycle = value[0];
            capsule->tag.subject = value[1];
            capsule->tag.sub = value[2];
            break;
        case ICF_TLV_RETENTION:
            if (tlv_len != 1) return ESP_ERR_INVALID_SIZE;
            capsule->retention = value[0];
            break;
        case ICF_TLV_EXPIRES:
            if (tlv_len != 4) return ESP_ERR_INVALID_SIZE;
            capsule->expires = READ_U32_BE(value);
            break;
        case ICF_TLV_BADGE_TYPE:
            if (tlv_len != 1) return ESP_ERR_INVALID_SIZE;
            capsule->badge_type = (icf_badge_type_t)value[0];
            break;
        case ICF_TLV_SYS_PAYLOAD:
            capsule->payload = malloc(tlv_len);
            if (!capsule->payload) return ESP_ERR_NO_MEM;
            memcpy(capsule->payload, value, tlv_len);
            capsule->payload_len = tlv_len;
            break;
        case ICF_TLV_HASH:
            if (tlv_len != 32) return ESP_ERR_INVALID_SIZE;
            memcpy(capsule->hash, value, 32);
            capsule->has_hash = true;
            break;
        case ICF_TLV_SIGNATURE:
            err = parse_tlv_signature(capsule, value, tlv_len);
            if (err != ESP_OK) return err;
            break;
        case ICF_TLV_AUTHORITY_ID:
            if (tlv_len != 8) return ESP_ERR_INVALID_SIZE;
            memcpy(capsule->authority_id, value, 8);
            capsule->has_authority = true;
            break;
        case ICF_TLV_END:
            if (tlv_len != 0) return ESP_ERR_INVALID_SIZE;
            got_end = true;
            break;
        default:
            // unknown TLV -> ignore
            break;
        }

        pos += tlv_len;

        if (type != ICF_TLV_HASH && type != ICF_TLV_SIGNATURE && type != ICF_TLV_AUTHORITY_ID)
            signed_len = pos; // update signed length until F2 encountered

        if (type == ICF_TLV_HASH) {
            // compute hash and compare
            uint8_t calc[crypto_hash_sha256_BYTES];
            crypto_hash_sha256(calc, buffer, signed_len);
            if (memcmp(calc, capsule->hash, 32) != 0) {
                return ESP_ERR_INVALID_CRC; // use CRC err for hash mismatch
            }
        }

        if (got_end) {
            break;
        }
    }

    if (pos != len) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

esp_err_t icf_parse_strict(const uint8_t *buffer, size_t len,
                           const uint8_t pubkey[32], icf_capsule_t *capsule)
{
    esp_err_t err = icf_parse(buffer, len, capsule);
    if (err != ESP_OK) {
        return err;
    }
    if (!capsule->has_signature || !capsule->has_authority) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!icf_verify(capsule, pubkey)) {
        return ESP_ERR_INVALID_CRC;
    }
    return ESP_OK;
}

bool icf_verify(const icf_capsule_t *capsule, const uint8_t pubkey[32])
{
    if (!capsule || !pubkey || !capsule->has_signature || !capsule->has_hash) {
        return false;
    }
    if (crypto_sign_verify_detached(capsule->signature, capsule->hash, 32, pubkey) == 0) {
        return true;
    }
    return false;
}

void icf_capsule_free(icf_capsule_t *capsule)
{
    if (!capsule) {
        return;
    }

    if (capsule->payload) {
        sodium_memzero(capsule->payload, capsule->payload_len);
        free(capsule->payload);
        capsule->payload = NULL;
        capsule->payload_len = 0;
    }

    sodium_memzero(capsule->hash, sizeof(capsule->hash));
    sodium_memzero(capsule->signature, sizeof(capsule->signature));
    capsule->has_hash = false;
    capsule->has_signature = false;
}

void icf_capsule_print(const icf_capsule_t *capsule)
{
    if (!capsule) return;
    printf("Badge type: %u\n", capsule->badge_type);
    if (capsule->url[0]) printf("URL: %s\n", capsule->url);
    if (capsule->language[0]) printf("Language: %s\n", capsule->language);
    if (capsule->title[0]) printf("Title: %s\n", capsule->title);
    printf("Tag: cycle=%u subject=%u sub=%u\n", capsule->tag.cycle, capsule->tag.subject, capsule->tag.sub);
    if (capsule->retention) printf("Retention: %u\n", capsule->retention);
    if (capsule->expires) printf("Expires: %u\n", capsule->expires);
    if (capsule->payload) {
        printf("Payload (%zu bytes): ", capsule->payload_len);
        fwrite(capsule->payload, 1, capsule->payload_len, stdout);
        printf("\n");
    }
    if (capsule->has_authority) {
        printf("AuthorityID: ");
        for (int i = 0; i < 8; ++i) printf("%02X", capsule->authority_id[i]);
        printf("\n");
    }
    if (capsule->has_signature) {
        printf("Signature present\n");
    }
}

