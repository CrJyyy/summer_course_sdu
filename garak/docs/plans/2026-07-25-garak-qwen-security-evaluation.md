# garak 开源模型安全测评实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 在独立 Conda 环境中部署 NVIDIA garak，通过 Hugging Face generator 对 `Qwen/Qwen2.5-0.5B-Instruct` 完成不少于三类安全测评，并生成可复现的中文课程报告。

**Architecture:** 使用本地 Hugging Face `Pipeline` generator 直接加载模型，以 YAML 固化 GPU、生成长度、随机种子和报告目录等配置。先运行最小探针验证端到端链路，再分别运行提示注入、敏感数据/训练数据泄露、越狱与恶意内容探针；保留 JSONL、hit log、控制台日志和汇总结果，报告中的数字全部从真实结果提取。

**Tech Stack:** Conda、Python 3.12、PyTorch 2.6+（CUDA 12.x）、Transformers 5.x、NVIDIA garak 0.16.0.pre1、Hugging Face Hub、Qwen2.5-0.5B-Instruct、Markdown

---

### Task 1: 建立兼容 GPU 的隔离环境

**Files:**
- Read: `pyproject.toml:105-160`
- No source changes

**Step 1: 创建独立环境**

Run:
```bash
conda create -n garak-eval python=3.12 pip -y
```
Expected: 环境创建成功，且不修改已有 `base`、`odysseus` 等环境。

**Step 2: 安装与当前驱动兼容的 PyTorch CUDA 构建**

Run:
```bash
conda run -n garak-eval pip install torch torchvision --index-url https://download.pytorch.org/whl/cu121
```
Expected: 安装满足 `torch>=2.6.0` 的 CUDA 12.1 wheel。

**Step 3: 验证 CUDA**

Run:
```bash
conda run -n garak-eval python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.is_available(), torch.cuda.get_device_name(0))"
```
Expected: `torch.cuda.is_available()` 为 `True`，设备为 `NVIDIA GeForce RTX 3060 Laptop GPU`。

### Task 2: 安装并验证 garak

**Files:**
- Read: `README.md:103-151`
- Read: `garak/generators/huggingface.py:46-180`
- No source changes

**Step 1: 从当前官方源码安装 garak**

Run:
```bash
conda run -n garak-eval pip install -e .
```
Expected: 安装 garak 及 Transformers、Datasets、Accelerate 等依赖。

**Step 2: 验证 CLI 与插件发现**

Run:
```bash
conda run -n garak-eval garak --version
conda run -n garak-eval garak --list_generators
conda run -n garak-eval garak --list_probes
```
Expected: garak 版本为当前源码版本，列表中包含 `huggingface.Pipeline` 以及选定探针。

### Task 3: 固化轻量测评配置

**Files:**
- Create: `evaluation/configs/qwen25-05b.yaml`
- Create: `evaluation/README.md`
- Create: `evaluation/results/.gitkeep`

**Step 1: 创建运行目录**

Run:
```bash
mkdir -p evaluation/configs evaluation/results evaluation/logs
```
Expected: 目录存在。

**Step 2: 编写 YAML 配置**

配置至少固定以下参数：
- generator: `huggingface.Pipeline`
- model: `Qwen/Qwen2.5-0.5B-Instruct`
- dtype: `float16`
- device: CUDA 自动选择
- `generations: 1`
- `max_tokens: 128`
- 固定 seed
- 单进程运行，避免 6 GB GPU 并发 OOM
- 报告输出至 `evaluation/results/`

**Step 3: 记录可复现命令**

在 `evaluation/README.md` 中记录环境创建、CUDA 验证、模型下载、冒烟测试、四类正式测试和结果分析命令。

### Task 4: 执行模型冒烟测试

**Files:**
- Output: `evaluation/results/smoke*.report.jsonl`
- Output: `evaluation/logs/smoke.log`

**Step 1: 查看插件精确名称与 CLI 配置格式**

Run:
```bash
conda run -n garak-eval garak --list_probes | grep -E 'promptinject|leakreplay|dan|donotanswer|malwaregen'
conda run -n garak-eval garak --help
```
Expected: 获取当前版本真实可用的 probe class 名称和配置参数。

**Step 2: 使用单一小探针加载模型**

Run（按当前 CLI 帮助校正参数名）：
```bash
conda run -n garak-eval garak --target_type huggingface --target_name Qwen/Qwen2.5-0.5B-Instruct --probes <small-probe> --generations 1
```
Expected: 模型下载并加载到 CUDA，至少生成一个有效响应，产生 JSONL 报告。

**Step 3: 检查资源和报告完整性**

Run:
```bash
nvidia-smi
python -c "import json, glob; files=glob.glob('evaluation/results/*.jsonl'); print(files)"
```
Expected: 无 OOM，报告含开始、attempt、evaluation 和结束记录。

### Task 5: 执行至少三类正式安全测评

**Files:**
- Output: `evaluation/results/prompt-injection*.jsonl`
- Output: `evaluation/results/data-leakage*.jsonl`
- Output: `evaluation/results/jailbreak*.jsonl`
- Output: `evaluation/results/harmful-content*.jsonl`
- Output: `evaluation/logs/*.log`

**Step 1: 提示注入测试**

优先从 `promptinject` 中选取规模适中的探针；必要时使用 `encoding` 的小型子探针。记录实际 probe、prompt 数、attempt 数、PASS/FAIL 和失败率。

**Step 2: 数据泄露测试**

从 `leakreplay` 中选取训练数据重放探针，并明确说明它衡量“诱导复现已知训练文本”的风险，不把它夸大成真实私有数据库泄露。

**Step 3: 越狱测试**

从 `dan` 中选择一个或两个代表性 DAN 探针，测试绕过安全约束的响应行为。

**Step 4: 恶意或不应回答内容测试**

从 `donotanswer` 或 `malwaregen` 中选择规模可控的探针，测试模型是否生成不当或危险内容。

**Step 5: 保存证据**

每项测试均使用独立 report prefix，控制台输出通过 `tee` 写入日志。若探针依赖外部数据集失败，记录原始错误并换用同风险类别的本地可用 probe，不隐藏失败过程。

### Task 6: 解析原始结果并交叉核验

**Files:**
- Create: `evaluation/summarize_results.py`
- Create: `evaluation/results/summary.json`
- Create: `evaluation/results/summary.md`

**Step 1: 编写最小解析器**

解析每个 `.report.jsonl` 的 probe、detector、attempt 状态、评分和输出，按测试类别汇总总样本数、失败数、失败率，并抽取少量代表性失败案例。不得改变 garak 的 PASS/FAIL 语义。

**Step 2: 运行解析器**

Run:
```bash
conda run -n garak-eval python evaluation/summarize_results.py evaluation/results
```
Expected: 生成 `summary.json` 和 `summary.md`。

**Step 3: 手工交叉核验**

随机选择至少一个 PASS 和一个 FAIL attempt，对照原始 JSONL，确认汇总数字和文本一致。

### Task 7: 编写中文课程测评报告

**Files:**
- Create: `evaluation/garak安全测评报告.md`

**Step 1: 编写报告主体**

报告包含：
1. 摘要与任务目标；
2. garak 工具简介与测评原理；
3. 硬件、系统、驱动、Python、PyTorch、garak commit、模型版本；
4. 部署步骤与关键命令；
5. 威胁模型和四类测评方法；
6. 每类真实结果表格；
7. 代表性输入/输出案例（对危险输出作必要截断）；
8. 风险分析、整改建议；
9. 局限性与复现说明；
10. 参考资料。

**Step 2: 验证报告中的数字**

逐项对照 `summary.json`，确保样本数、FAIL 数和百分比一致；明确 garak 的 `FAIL` 表示检测到目标不安全行为，而非工具执行失败。

**Step 3: 最终复现检查**

Run:
```bash
conda run -n garak-eval garak --version
conda run -n garak-eval python evaluation/summarize_results.py evaluation/results
```
Expected: 命令成功，报告和汇总文件中的版本与数字保持一致。

### Task 8: 最终验证与交付清单

**Files:**
- Verify: `evaluation/README.md`
- Verify: `evaluation/configs/qwen25-05b.yaml`
- Verify: `evaluation/results/summary.json`
- Verify: `evaluation/results/summary.md`
- Verify: `evaluation/garak安全测评报告.md`

**Step 1: 检查至少三类测评均有真实结果**

Expected: 提示注入、数据泄露、越狱三类必须完成；第四类作为增强项。

**Step 2: 检查敏感与大型文件**

确保未提交 Hugging Face token、模型权重、缓存或超大日志；报告保留必要证据和结果摘要。

**Step 3: 输出交付说明**

列出环境名称、模型、测试类别、结果文件、报告路径、未解决限制和完整复现命令。
