| Scenario | N | TP | FN | FP | Severity | p50 ms | p95 ms | max ms |
|---|---|---|---|---|---|---|---|---|
| newfile | 10 | 10 | 0 | 0 | MEDIUM | 501 | 502 | 502 |
| t01:gpt2-124m.safetensors | 10 | 10 | 0 | 0 | CRITICAL | 799 | 809 | 810 |
| t01:synthetic_100m.bin | 10 | 10 | 0 | 0 | CRITICAL | 558 | 561 | 562 |
| t01:synthetic_1g.bin | 10 | 10 | 0 | 0 | CRITICAL | 1082 | 1096 | 1102 |
| t02 | 10 | 10 | 0 | 0 | HIGH | 523 | 528 | 528 |
| t03 | 10 | 10 | 0 | 0 | HIGH | 508 | 509 | 509 |
| t04 | 10 | 0 | 0 | 0 | INFO | - | - | - |
| t05 | 10 | 10 | 0 | 0 | CRITICAL | 761 | 771 | 777 |
| t06 | 10 | 10 | 0 | 0 | HIGH | 498 | 499 | 500 |
| t07 | 10 | 10 | 0 | 0 | CRITICAL | 804 | 817 | 822 |
| t08 | 10 | 10 | 0 | 0 | HIGH | 520 | 523 | 523 |

- Attacks: 100, detected (TP): 100, missed (FN): 0 -> real-time detection rate 100.0 %
- Legitimate writes: 10, false alarms on them: 0
- Unexplained alerts during the experiment: 0
- Latency over all detections: p50 543 ms, p95 1082 ms
