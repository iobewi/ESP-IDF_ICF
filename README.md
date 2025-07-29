# ESP-IDF ICF Component

This repository provides a simple ESP-IDF component named `icf` used to parse
and verify IOBEWI Capsule Format (ICF) capsules. An example project is provided
in `examples/icf_decode`.

The component exposes the following API:

```c
esp_err_t icf_parse(const uint8_t *buffer, size_t len, icf_capsule_t *capsule);
bool icf_verify(const icf_capsule_t *capsule, const uint8_t pubkey[32]);
void icf_capsule_print(const icf_capsule_t *capsule);
void icf_capsule_free(icf_capsule_t *capsule);
```

Unit tests are located in `tests/` and can be run with the ESP-IDF
`unity` test runner.
