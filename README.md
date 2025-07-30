[![Build firmware](https://github.com/iobewi/ESP-IDF_ICF/actions/workflows/build.yml/badge.svg)](https://github.com/iobewi/ESP-IDF_ICF/actions/workflows/build.yml) 
[![CodeQL analysis](https://github.com/iobewi/ESP-IDF_ICF/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/iobewi/ESP-IDF_ICF/actions/workflows/codeql-analysis.yml)  

# 📦 ICF – IOBEWI Capsule Format (ESP-IDF Component)

**ICF** est une bibliothèque C compatible ESP-IDF permettant de décoder, vérifier et exploiter des capsules RFID au format TLV définies dans le cadre du projet [Balabewi](https://www.iobewi.com).

Chaque capsule encode des métadonnées signées (type, URL, langue, titre, tags pédagogiques…) et des instructions système (payload chiffré), le tout vérifiable par signature Ed25519.

---

## ✨ Fonctionnalités

- 📦 Décodage de capsules au format TLV (Type-Length-Value)
- 🆔 Prise en charge des types de badge : ressource, configuration, administration
- 🔐 Vérification Ed25519 de la signature (via [libsodium](https://doc.libsodium.org/))
- 🔍 Vérification stricte avec exigence de signature et d'identité d'autorité
- 📜 Extraction vers JSON via [cJSON](https://github.com/DaveGamble/cJSON)
- ✅ Intégré aux outils de test ESP-IDF via Unity

---

## 📁 Structure du composant

```bash
icf/
├── include/icf/icf.h         # API publique
├── src/icf.c                 # Implémentation
├── test/test_icf.c          # Tests unitaires (Unity)
├── idf_component.yml         # Déclaration ESP-IDF
```

---

## ⚙️ Intégration dans un projet ESP-IDF

Ajoutez ce composant à votre dossier `components/` :

```bash
components/
└── icf/
    ├── include/icf/icf.h
    ├── src/icf.c
    └── ...
```

Puis dans votre `CMakeLists.txt` de composant principal :

```cmake
idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES icf
)
```

Et dans `main.c` :

```c
#include "icf/icf.h"
```

---

## 🧪 Exemple d'utilisation

```c
#include "icf/icf.h"

void app_main() {
    const uint8_t raw_capsule[] = { 0x01, 0x05, 'h','e','l','l','o', 0xFF, 0x00 };
    icf_capsule_t capsule;

    if (icf_parse(raw_capsule, sizeof(raw_capsule), &capsule) == ESP_OK) {
        printf("URL: %s\n", capsule.url);
    } else {
        printf("Erreur de parsing\n");
    }
}
```

---

## 🔒 Vérification stricte

```c
extern uint8_t public_key[32];

esp_err_t res = icf_parse_strict(
    capsule_data,
    capsule_len,
    public_key,
    &capsule
);
```

---

## 🧪 Lancer les tests

Depuis le dossier `test/`, lancez :

```bash
idf.py build && idf.py flash monitor
```

Les tests unitaires sont définis avec `Unity` et couvrent les cas nominaux, les erreurs de parsing, les signatures invalides, etc.

---

## 🧰 Dépendances

| Dépendance  | Rôle              | Notes                               |
| ----------- | ----------------- | ----------------------------------- |
| `libsodium` | Signature Ed25519 | Fournie par ESP-IDF (`esp-sodium`)  |
| `cJSON`     | Manipulation JSON | Requise si payload JSON est utilisé |

---

## 📖 Format TLV supporté

- Spécification du IOBEWI Capsule Format [ICF](https://github.com/iobewi/icf/blob/main/doc/SPEC-ICF.md)


---

## 📜 Licence

Code source sous **MPL 2.0**
Spécifications associées sous **CC-BY-SA 4.0**

---

## 🤝 Projet Balabewi

Ce composant est utilisé dans le cadre du projet [Balabewi](https://www.iobewi.com) – un lecteur audio open source, activé par badge RFID, conçu pour l’éducation, la culture et la famille.

---

## 📬 Contact

> [contact@iobewi.com](mailto:contact@iobewi.com)
> [https://github.com/iobewi/ESP-IDF\_ICF](https://github.com/iobewi/ESP-IDF_ICF)
