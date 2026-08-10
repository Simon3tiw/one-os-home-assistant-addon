# ONE.OS selected configuration snapshot contract V1

Deze directory is de runtime-onafhankelijke contractbron voor Fase 2B.3.

## Verplicht validatieprofiel

`configuration-snapshot-v1.schema.json` is bewust alleen het **structurele** contract. Iedere producer en consumer MOET daarna `semantic_validator.py` uitvoeren. Die dependency-light Python-validator (standaardbibliotheek, Python 3.11+) normeert:

- per nodekind strikt oplopende, unieke ID's;
- ID-uniciteit over alle vier nodekinderen;
- lokale Structure→Space→Asset→Point-referenties;
- exact de gesloten V1 `valueType`/`canonicalUnit`/`displayUnit`/`decimals`-matrix;
- een echte RFC3339 UTC-tijd met hoofdletter `Z` (fractionele seconden toegestaan, offsets niet).

Voor `number` zijn beide units samen `null`, of staat het paar in `V1_DISPLAY_UNITS`; `decimals` mag daarbij `null` of 0–9 zijn. Voor `boolean`, `string` en `enum` zijn units én `decimals` exact `null`. Een uitbreiding van de unitmatrix vereist een nieuw contractversion.

`semantic-vectors.json` bevat positieve en negatieve executable vectors met stabiele foutcodes. Central draait dezelfde vectors tegen zowel de gedeelde validator als `app/configuration_snapshot_v1.py` en eist resultaat- én codepariteit.

Verificatie vanuit de repositoryroot:

```console
$ python3 contracts/configuration-snapshot/v1/verify_vector.py
configuration_snapshot_v1_vector=exact
$ python3 contracts/configuration-snapshot/v1/verify_semantics.py
configuration_snapshot_v1_semantic_vectors=exact cases=36
```

## Canonicalisatie en datagrens

Canonical projectiebytes zijn UTF-8 JSON van exact de vier arrays `structures`, `spaces`, `assets` en `points`, objectsleutels lexicografisch gesorteerd, arrays oplopend op `id`, separators `,` en `:`, geen insignificant whitespace en `ensure_ascii=false`. `projectionSha256` is strict unpadded base64url van SHA-256 over die bytes.

Alleen effectief geselecteerde Points en hun minimale ONE.OS-parentcontext mogen worden opgenomen. Home Assistant-bron-ID’s, raw attributes, niet-geselecteerde nodes, actuele waarden en secrets zijn verboden.
