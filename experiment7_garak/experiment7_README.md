# garak + Qwen2.5-0.5B 安全测评

## 环境

- Conda 环境：`garak-eval`
- 被测模型：`Qwen/Qwen2.5-0.5B-Instruct`
- generator：`huggingface.Pipeline`
- 公共配置：`evaluation/configs/qwen25-05b.yaml`

## 环境验证

```bash
conda run -n garak-eval python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.is_available(), torch.cuda.get_device_name(0))"
conda run -n garak-eval garak --version
```

## 冒烟测试

```bash
conda run -n garak-eval garak \
  --config evaluation/configs/qwen25-05b.yaml \
  --target_type huggingface.Pipeline \
  --target_name Qwen/Qwen2.5-0.5B-Instruct \
  --spec probes.leakreplay.GuardianComplete \
  --report_prefix smoke
```

## 正式测评

```bash
# 提示注入
conda run -n garak-eval garak --config evaluation/configs/qwen25-05b.yaml --target_type huggingface.Pipeline --target_name Qwen/Qwen2.5-0.5B-Instruct --spec probes.promptinject.HijackHateHumans --report_prefix prompt-injection

# 数据泄露/训练数据重放
conda run -n garak-eval garak --config evaluation/configs/qwen25-05b.yaml --target_type huggingface.Pipeline --target_name Qwen/Qwen2.5-0.5B-Instruct --spec probes.leakreplay.GuardianComplete --report_prefix data-leakage

# 越狱
conda run -n garak-eval garak --config evaluation/configs/qwen25-05b.yaml --target_type huggingface.Pipeline --target_name Qwen/Qwen2.5-0.5B-Instruct --spec probes.dan.DanInTheWild --report_prefix jailbreak

# 恶意代码生成
conda run -n garak-eval garak --config evaluation/configs/qwen25-05b.yaml --target_type huggingface.Pipeline --target_name Qwen/Qwen2.5-0.5B-Instruct --spec probes.malwaregen.TopLevel --report_prefix harmful-content
```

`FAIL` 表示探针检测到目标不安全行为，不表示 garak 运行失败。原始报告为 `*.report.jsonl`，命中记录为 `*.hitlog.jsonl`。
