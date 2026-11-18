### Table 7. Projected drone-side cost per exchange component (published timings x exact op counts)

| component | AVR_ms | CortexM4_ms | CortexM4_mJ | RPiB+_ms |
|---|---|---|---|---|
| RLA-IoD drone, cold | 1.213e+04 | 1061 | 35.01 | 42.8 |
| RLA-IoD drone, cert cached | 9476 | 752 | 24.82 | 33.6 |
| + precomputed ephemeral key | 7256 | 608 | 20.06 | 25.7 |
| RLA-IoD GCS side | 1.213e+04 | 1061 | 35.01 | 42.8 |
| Static-ECDH design, drone | 9906 | 917 | 30.26 | 34.9 |
| One DH ratchet, either side | 4440 | 288 | 9.504 | 15.8 |
