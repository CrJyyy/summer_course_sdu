# 山东大学2026网络安全创新创业实践课

## 👥 小组成员与分工

| 成员 | 学号 | 负责任务 | 主要工作 |
|:---:|:---:|:---:|---|
| **冀芯如** | `202300460003` | 任务 1、任务 4 | Bitcoin Testnet4 交易与区块解析；SM3 软件实现与优化 |
| **朱仪烜** | `202300460031` | 任务 5、任务 6 | 全同态密文卷积；旋转次数最小化分析 |
| **项姝捷** | `202300350033` | 任务 1、任务 2、任务 3 | Bitcoin 实验；libsecp256k1 研究；对称密码实现与优化 |
| **高姗** | `202300460081` | 任务 7 | garak 部署、开源大模型安全测评与报告撰写 |

## 📚 项目总览

| 文件夹 | 对应任务 | 完成内容 | 报告 | 复现入口 |
|---|---|---|---|---|
| [`experiments_1_2_bitcoin`](experiments_1_2_bitcoin/) | 任务 1、2 | Testnet4 交易与完整区块解析；libsecp256k1 安全和性能研究 | [任务 1 PDF](experiments_1_2_bitcoin/01_testnet4_tx_block/output/pdf/task1_testnet4_tx_block.pdf) · [任务 2 PDF](experiments_1_2_bitcoin/02_secp256k1_report/output/pdf/task2_secp256k1_report.pdf) | [总说明](experiments_1_2_bitcoin/README.md) |
| [`experiment_3_symmetric_cipher`](experiment_3_symmetric_cipher/) | 任务 3 | AES、SM4、GIFT、TWINE 及 CTR/GCM/XTS 优化 | [完整报告 PDF](experiment_3_symmetric_cipher/output/pdf/symmetric_cipher_software_optimization.pdf) | [README](experiment_3_symmetric_cipher/README.md) · [实现映射](experiment_3_symmetric_cipher/TASK_IMPLEMENTATION_MAP.md) |
| [`experiment4_SM3`](experiment4_SM3/) | 任务 4 | x86-64 AVX2/AVX512 与 ARM64 NEON+GPR 混合优化 | [SM3 实验报告](experiment4_SM3/SM3_REPORT.md) | [README](experiment4_SM3/README.md) |
| [`experiment5_6_fhe_convolution`](experiment5_6_fhe_convolution/) | 任务 5、6 | CKKS 密文卷积与旋转次数理论分析 | [实验报告与说明](experiment5_6_fhe_convolution/README.md) | [主程序](experiment5_6_fhe_convolution/fhe_convolution.py) |
| [`experiment7_garak`](experiment7_garak/) | 任务 7 | garak 部署及四类大模型安全测评 | [安全测评报告](experiment7_garak/garak安全测评报告.md) | [复现说明](experiment7_garak/experiment7_README.md) · [结果汇总](experiment7_garak/garak/evaluation/results/summary.md) |

## 🔬 各任务完成情况

### 任务 1：Bitcoin Testnet4 交易与区块解析

对应课程图片中的要求：在 Bitcoin 测试网发送一笔交易，将交易数据解析到每个
bit/byte，并解析完整区块及其中的脚本和字段。

本项目完成了真实 Testnet4 P2WPKH 交易的本地构造、签名、广播与确认，并实现：

- 交易输入、输出、Coinbase 交易、锁定脚本和解锁数据的解析；
- TXID、WTXID、BIP143 签名摘要、ECDSA 签名与金额守恒验证；
- 完整区块逐字节无缺口解析；
- 区块头、Merkle root、难度目标、Nonce 和 PoW 验证；
- JSON 层级结果与逐字节 CSV 输出。

报告与复现：

- [任务 1 PDF 报告](experiments_1_2_bitcoin/01_testnet4_tx_block/output/pdf/task1_testnet4_tx_block.pdf)
- [任务 1 Markdown 报告](experiments_1_2_bitcoin/01_testnet4_tx_block/output/pdf/task1_testnet4_tx_block.md)
- [程序、数据和完整复现说明](experiments_1_2_bitcoin/01_testnet4_tx_block/README.md)

利用仓库中已经保存的公开链上数据进行本地验证：

```bash
cd experiments_1_2_bitcoin/01_testnet4_tx_block
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/btc-lab verify
```

若要重新构造和广播交易，还需 Testnet4 网络访问以及 faucet 测试币；测试币没有
现实价值。私钥仅允许保存在已忽略的 `.secrets/` 中，不得提交、截图或写入报告。

### 任务 2：libsecp256k1 安全与性能研究

对应课程图片中的要求：研究
[`bitcoin-core/secp256k1`](https://github.com/bitcoin-core/secp256k1)
中的密码算法应用、安全漏洞修复和性能改进，并解释其原因与数学原理。

项目分析了编译器引入的 constant-time 安全回归、ECDSA 验证器信任外部摘要时的
存在性伪造、固定基点乘法重构和预计算表大小调整，并保存了固定版本、上游提交、
源码差异、官方测试、性能测试与库大小数据。

报告与复现：

- [任务 2 PDF 报告](experiments_1_2_bitcoin/02_secp256k1_report/output/pdf/task2_secp256k1_report.pdf)
- [任务 2 Markdown 报告](experiments_1_2_bitcoin/02_secp256k1_report/output/pdf/task2_secp256k1_report.md)
- [复现范围与结果说明](experiments_1_2_bitcoin/02_secp256k1_report/README.md)
- [一键复现脚本](experiments_1_2_bitcoin/02_secp256k1_report/scripts/reproduce.py)

```bash
cd experiments_1_2_bitcoin/02_secp256k1_report
python3 -m venv .venv
.venv/bin/python -m pip install cmake ninja
.venv/bin/python scripts/reproduce.py --case all --runs 10 --warmups 2
.venv/bin/python scripts/forge_digest_demo.py
```

完整复现需要联网下载固定版本的上游源码，并需要 Clang、CMake 和 Ninja。已有报告
中的原始日志记录的是实验当时的绝对路径，作为实验环境证据予以保留。

### 任务 3：对称密码算法的软件实现与优化

从可审计的基础实现出发，完成 AES、SM4、GIFT 和 TWINE 的加解密，并覆盖：

- AES 与 SM4 的 T-table 优化；
- ARM NEON `TBL`、x86 `PSHUFB` 和 GIFT bitslice/shuffle 路径；
- AES-NI/VAES、PMULL/PCLMUL、GFNI 和 SM4 专用指令等新指令方法；
- AES/SM4/GIFT/TWINE 的 CTR，以及 AES/SM4 的 GCM、XTS 优化实现；
- ARM64 与 x86 的正确性、指令反汇编和性能验证。

报告与复现：

- [对称密码优化 PDF 报告](experiment_3_symmetric_cipher/output/pdf/symmetric_cipher_software_optimization.pdf)
- [项目说明](experiment_3_symmetric_cipher/README.md)
- [课程要求与代码实现位置对照](experiment_3_symmetric_cipher/TASK_IMPLEMENTATION_MAP.md)

```bash
cd experiment_3_symmetric_cipher
make test
make bench
make report
```

不同 ISA 后端需要在对应的 ARM64 或 x86 设备上验证；部分差分测试还需要
OpenSSL 3.6 或兼容版本。`make all` 可执行项目提供的完整验证与报告流程。

### 任务 4：SM3 软件实现与优化

完成 SM3 标准 C 基线实现，以及两类架构的 SIMD 与通用寄存器混合优化：

- x86-64：AVX2/AVX512 完成宽位加载、字节序转换和向量化异或，GPR 执行
  64 轮展开压缩；
- ARM64：NEON 完成数据加载和字节序转换，结合 GPR 滑动窗口与 on-the-fly
  消息扩展。

报告与复现：

- [SM3 完整实验报告](experiment4_SM3/SM3_REPORT.md)
- [编译、测试和性能结果说明](experiment4_SM3/README.md)

```bash
cd experiment4_SM3/code

# ARM64
clang -O3 -o sm3_arm64 sm3_arm64.c
./sm3_arm64

# x86-64
gcc -O3 -mavx2 -mavx512f -mavx512bw sm3_x86.c -o sm3_x86
./sm3_x86
```

应在对应架构上执行相应程序；CPU 或虚拟机未提供所需指令集时，x86 程序会回退
到可用路径。

### 任务 5：全同态密文卷积

选择 Microsoft SEAL 的 TenSEAL Python 绑定和 CKKS 方案，将单输入单输出
`4×4` 输入按行主序打包到一个密文中，对 `3×3` 卷积核执行步长为 1、无填充的
密文卷积，得到 `2×2` 输出，并通过解密结果与明文卷积结果的误差验证正确性。

### 任务 6：旋转次数最小值分析

采用“打包 → 旋转 → 累加”策略。对于一般密集 `3×3` 卷积核，除零位移外的
8 个不同位移均需要旋转，因此理论最小值为 8 次；本实验使用的 Sobel-X 类卷积核
只有 6 个非零权值，实际跳过零权值后执行 5 次旋转，达到该稀疏卷积核下的最小值。

任务 5/6 当前由同一个 README 承担实验报告、算法分析和复现指南：

- [任务 5/6 实验报告与复现说明](experiment5_6_fhe_convolution/README.md)
- [密文卷积主程序](experiment5_6_fhe_convolution/fhe_convolution.py)

```bash
cd experiment5_6_fhe_convolution
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python fhe_convolution.py
```

首次运行需要安装 `numpy` 与 `tenseal`。CKKS 是近似计算方案，解密结果允许存在
量级很小的浮点误差。

### 任务 7：基于 garak 的开源大模型安全测评

在本地部署 garak，并以 `Qwen/Qwen2.5-0.5B-Instruct` 为被测模型，完成了
537 次模型交互，覆盖四项安全测评：

1. 提示注入；
2. 训练数据重放/数据泄露；
3. DAN 越狱；
4. 恶意代码生成。

报告与复现：

- [garak 安全测评报告](experiment7_garak/garak安全测评报告.md)
- [环境、命令与复现说明](experiment7_garak/experiment7_README.md)
- [测评结果汇总](experiment7_garak/garak/evaluation/results/summary.md)

```bash
cd experiment7_garak/garak
conda run -n garak-eval garak \
  --config evaluation/configs/qwen25-05b.yaml \
  --target_type huggingface.Pipeline \
  --target_name Qwen/Qwen2.5-0.5B-Instruct \
  --spec probes.leakreplay.GuardianComplete \
  --report_prefix smoke
```

完整测评命令见复现说明。首次运行需要下载模型；建议使用具备足够显存的 GPU，
也可在资源允许时使用 CPU。garak 输出中的 `FAIL` 表示模型输出命中不安全行为，
不表示测评程序运行失败。

## ⚙️ 环境与复现提示

| 实验 | 主要环境要求 |
|---|---|
| 任务 1 | Python 3、Testnet4 网络；重新广播时需要 faucet 测试币 |
| 任务 2 | Python 3、Clang、CMake、Ninja、Git 和网络访问 |
| 任务 3 | C11 编译器、Make；跨架构验证需要 ARM64/x86 设备，差分测试需要 OpenSSL |
| 任务 4 | ARM64 NEON 或 x86-64 AVX2/AVX512 对应硬件与编译器 |
| 任务 5/6 | Python 3、NumPy、TenSEAL/Microsoft SEAL |
| 任务 7 | Conda、PyTorch、Transformers、garak；推荐使用 GPU |

