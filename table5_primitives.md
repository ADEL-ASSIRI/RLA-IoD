### Table 5. Per-operation cost (host measured; others published, see costmodel.py)

| Operation | Host_ms | Host_CI95 | AVR_ms | Cortex-M4_ms | RPi B+_ms |
|---|---|---|---|---|---|
| ECC scalar multiplication (ECDH) | 0.06603 | 0.0008597 | 2220 | 144 | 7.9 |
| ECDSA sign | 0.03311 | 0.002746 | 2386 | 155 | 8.6 |
| ECDSA verify | 0.1312 | 0.03478 | 2650 | 309 | 9.2 |
| HKDF (32 B) | 0.005749 | 0.0008324 | negligible | negligible | negligible |
| HMAC-SHA-256 | 0.001543 | 3.167e-05 | negligible | negligible | negligible |
| SHA-256 | 0.0005621 | 9.809e-06 | negligible | negligible | negligible |
