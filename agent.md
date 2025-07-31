# Agent: ICF Decoder

Ce projet expose une bibliothèque C pour décoder, vérifier et manipuler des capsules RFID au format TLV signées, utilisées dans le cadre du projet open source **Balabewi**. L'agent est basé sur un composant ESP-IDF compatible avec les microcontrôleurs ESP32-S3.

## 🧠 Capacité de l’agent

Cet agent peut :

- Décoder un flux binaire TLV représentant une capsule ICF (IOBEWI Capsule Format)
- Extraire les champs utiles : URL, langue, titre, tags pédagogiques, etc.
- Vérifier une signature Ed25519 via `libsodium`
- Exposer la capsule au format JSON (si compilé avec `cJSON`)
- Gérer plusieurs types de badges : ressource, configuration, administration
- Fonctionner en mode "libre" ou "bridé" (signature obligatoire)

## 🧩 Entrées attendues

### 1. Flux binaire de capsule (tableau de `uint8_t`)
- Doit être un encodage TLV valide, respectant la [spécification ICF v1](doc/SPEC-ICF.md)
- Exemple minimal : `{ 0x01, 0x05, 'h','e','l','l','o', 0xFF, 0x00 }`

### 2. (Optionnel) Callback `lookup(id[8]) → pubkey[32]`
- Si mode bridé, permet de retrouver la clé publique associée à une autorité via son ID (champ `0xF4`)

## 📤 Sorties

### 1. Structure `icf_capsule_t`
- Contient tous les champs de métadonnées extraits
- Accès via `capsule.url`, `capsule.language`, `capsule.badge_type`, etc.

### 2. (optionnel) Sortie JSON via `icf_capsule_to_json()`

### 3. Code retour `esp_err_t`
- `ESP_OK` si succès
- `ESP_ERR_INVALID_ARG`, `ESP_ERR_NO_MEM`, etc. selon l'erreur

## 🔒 Sécurité

- Utilise SHA256 + Ed25519 pour vérifier l’authenticité du contenu
- Signature incluse dans les champs `0xF2` (hash), `0xF3` (signature), `0xF4` (authority ID)
- Rejette les capsules invalides si `strict = true`

## 🔧 Dépendances

- `libsodium` (via `esp-sodium`) pour la vérification Ed25519
- `cJSON` (optionnel) pour l'export JSON
- ESP-IDF (>= 5.0)

## 🔁 Fonctionnement

```c
#include "icf/icf.h"

icf_capsule_t capsule;
esp_err_t err = icf_parse(data, len, &capsule, strict_mode, authority_lookup);
```

* `strict_mode = false` → accepte tout TLV valide
* `strict_mode = true` → nécessite signature et clé publique valide

## 🧪 Tests

* L’agent inclut des tests unitaires (`test/test_icf.c`)
* Lancement via `idf.py build && idf.py flash monitor`
* Couvre les cas : parsing simple, signature invalide, absence de signature, lookup dynamique, etc.

## 📎 Références

* [Spécification ICF v1](https://github.com/iobewi/icf/blob/main/doc/SPEC-ICF.md)
* [Projet Balabewi](https://www.iobewi.com)
* [Ed25519 – RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)

## 📜 Licence

* Code source : MPL 2.0
* Spécification : CC-BY-SA 4.0

## 💬 Contact

* Mainteneur : Lionel ORCIL – [contact@iobewi.com](mailto:contact@iobewi.com)
* GitHub : [https://github.com/iobewi/ESP-IDF\_ICF](https://github.com/iobewi/ESP-IDF_ICF)
