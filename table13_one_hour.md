### Table 13. One hour at 10 msg/s (Cortex-M4 costs, 33 mW core)

| Policy | CPU_s_per_h | Duty_pct | Energy_J_per_h | Exposed_per_1000 |
|---|---|---|---|---|
| Re-handshake every 300 s (static timeout) | 15.78 | 0.4383 | 0.5207 | 679 |
| Fixed DH-ratchet span L = 3 | 3460 | 96.11 | 114.2 | 0.453 |
| Fixed DH-ratchet span L = 50 | 211.7 | 5.88 | 6.985 | 11.8 |
| Fixed DH-ratchet span L = 500 | 25.06 | 0.696 | 0.8268 | 117.8 |
| RLA-IoD adaptive (mu = 30) | 50.03 | 1.39 | 1.651 | 40.47 |
| RLA-IoD adaptive (mu = 100) | 75.17 | 2.088 | 2.481 | 18.64 |
| RLA-IoD adaptive (mu = 300) | 116.6 | 3.24 | 3.849 | 8.301 |
