[![Build firmware](https://github.com/iobewi/ESP-IDF_ICF/actions/workflows/build.yml/badge.svg)](https://github.com/iobewi/ESP-IDF_ICF/actions/workflows/build.yml) 
[![CodeQL analysis](https://github.com/iobewi/ESP-IDF_ICF/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/iobewi/ESP-IDF_ICF/actions/workflows/codeql-analysis.yml)  

# ESP-IDF ICF Component

This repository provides a simple ESP-IDF component named `icf` used to parse
and verify IOBEWI Capsule Format (ICF) capsules. An example project is provided
in `examples/icf_decode`.

## Getting Started

You can add this component to an ESP-IDF project using the component manager:

```bash
idf.py add-dependency iobewi/ESP-IDF_ICF^1
```

An example application demonstrating the API is available in
`examples/icf_decode`. To build and flash the example run:

```bash
idf.py -B build -C examples/icf_decode flash monitor
```

## API

The component exposes the following API:

```c
esp_err_t icf_parse(const uint8_t *buffer, size_t len, icf_capsule_t *capsule);
esp_err_t icf_parse_strict(const uint8_t *buffer, size_t len,
                           const uint8_t pubkey[32], icf_capsule_t *capsule);
bool icf_verify(const icf_capsule_t *capsule, const uint8_t pubkey[32]);
void icf_capsule_print(const icf_capsule_t *capsule);
void icf_capsule_free(icf_capsule_t *capsule);
```

`icf_parse_strict()` is a convenience wrapper combining parsing and signature
verification. It returns an error if the capsule lacks a signature or an
authority ID, or if the signature verification fails.

## Running Tests

Unit tests are located in `components/icf/test/` and can be executed
with the ESP-IDF `unity` test runner using:

```bash
idf.py test
```

