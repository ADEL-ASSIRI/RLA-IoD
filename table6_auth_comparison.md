### Table 6. Authentication comparison (host measured)

| Scheme | Drone_CPU_ms | GCS_CPU_ms | Wire_bits | Drone_PK_ops | Forward_secrecy | Identity_hidden_from_GCS |
|---|---|---|---|---|---|---|
| PSK-HMAC | 0.00811 | 0.008096 | 832 | 0 | no | no |
| Static-ECDH design | 0.4364 | 0.273 | 2408 | 4 | no | no |
| RLA-IoD, GCS cert cached | 0.3276 | 0.4735 | 3160 | 4 | yes | yes |
| RLA-IoD, cold | 0.5607 | 0.567 | 4032 | 5 | yes | yes |
