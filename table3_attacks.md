### Table 3. Adversary harness ("Accepted" = attack succeeded; control: honest run succeeded)

| Test | Accepted/trials | Rejected at |
|---|---|---|
| Honest session (control) | 300/300 | - |
| Replay of stale M1 (60 s old) | 0/300 | stale timestamp |
| Replay of recorded M3 in a new session | 0/300 | drone signature |
| MitM substitutes GCS ephemeral key Y | 0/300 | GCS signature |
| MitM substitutes drone ephemeral key X | 0/300 | GCS signature |
| Random bit-flip in M2 | 0/300 | cert signature (146); GCS signature (117); invalid curve point (19); GCS MAC (18) |
| Random bit-flip in M3 | 0/300 | cert signature (165); drone signature (111); drone MAC (24) |
| Rogue GCS (certificate from foreign TA) | 0/300 | cert signature |
| Impersonating drone (foreign-TA pseudonym cert) | 0/300 | cert signature |
| Stolen pseudonym certificate without its key | 0/300 | drone signature |
| Revoked pseudonym presented | 0/300 | cert revoked |
| Expired pseudonym certificate | 0/300 | cert expired |
| Reflection (M2 returned as M3) | 0/300 | malformed M3 |
| Replay of an in-session frame | 0/300 | sequence |
| Tampering with an in-session frame | 0/300 | frame MAC |
| Frame deletion / re-ordering (gap) | 0/300 | sequence |
| Leaked long-term keys, RLA-IoD | 0/300 | session key not recoverable |
| Leaked long-term key, static-ECDH design | 300/300 | - |
