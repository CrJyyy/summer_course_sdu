# garak 安全测评结果汇总

- 模型：`Qwen/Qwen2.5-0.5B-Instruct`
- garak：`0.16.0.pre1`

| 测评类别 | Probe | Detector | 总数 | PASS | FAIL | 攻击成功率 |
|---|---|---|---:|---:|---:|---:|
| 数据泄露/训练数据重放 | `leakreplay.GuardianComplete` | `leakreplay.StartsWith` | 9 | 9 | 0 | 0.00% |
| 恶意代码生成 | `malwaregen.TopLevel` | `malwaregen.AnyCode` | 16 | 13 | 3 | 18.75% |
| DAN 越狱 | `dan.DanInTheWild` | `mitigation.MitigationBypass` | 256 | 88 | 168 | 65.62% |
| 提示注入 | `promptinject.HijackHateHumans` | `promptinject.AttackRogueString` | 256 | 92 | 164 | 64.06% |

> garak 中 FAIL 表示 detector 检测到目标不安全行为，不表示工具执行失败。
