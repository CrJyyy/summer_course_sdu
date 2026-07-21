# Task 1 - Testnet4 transaction and full-block parser

该项目不依赖 Bitcoin Core 节点即可完成一次真实 Testnet4 P2WPKH 交易。密钥与签名在本机完成，公共 Esplora API 仅用于读取 UTXO、广播原始交易和下载已确认区块。

## 目录与主要文件

```text
01_testnet4_tx_block/
├── src/btc_lab/       # 交易构造、签名、解析与命令行源码
├── tests/             # 单元测试
├── data/              # 一次实验的状态文件与原始链上字节
├── output/data/       # 可提交的结构化解析结果
├── output/pdf/        # 最终课程报告 PDF
├── report/            # LaTeX 源文件、截图和编译说明
├── .secrets/          # 本地私钥（禁止提交或截图）
├── .venv/             # Python 虚拟环境（可重新创建）
├── tmp/               # LaTeX 临时文件和逐页渲染结果
├── pyproject.toml     # Python 项目、依赖和命令行入口配置
└── README.md          # 本说明文件
```

各目录中的主要文件及用途如下。

| 路径 | 主要文件 | 用途 |
|---|---|---|
| 项目根目录 | `pyproject.toml` | 声明 Python 版本、`coincurve`/`pytest` 依赖、`btc-lab` 命令行入口和测试配置。 |
| `src/btc_lab/` | `cli.py`、`__main__.py` | 实现 `wallet-init`、`funding-status`、`build`、`broadcast`、`fetch-confirmation`、`parse-tx`、`parse-block`、`verify` 等统一命令。 |
| `src/btc_lab/` | `encoding.py`、`models.py` | CompactSize、字节序、哈希、Bech32 等基础编码，以及交易/输入/输出数据模型。 |
| `src/btc_lab/` | `wallet.py`、`transaction.py` | 生成一次性 P2WPKH 钱包；构造 BIP143 摘要、ECDSA 签名、序列化交易并计算 TXID/WTXID、weight/vsize 和手续费。 |
| `src/btc_lab/` | `block.py`、`script.py` | 逐字节解析完整区块与交易，验证 Merkle root/PoW，并分类和反汇编常见 Bitcoin Script。 |
| `src/btc_lab/` | `network.py`、`io_utils.py` | 调用 Testnet4 Esplora API，并以安全、可重复的方式读写 JSON、CSV 和原始十六进制数据。 |
| `tests/` | `test_encoding.py` | 测试 CompactSize 边界、端序、非法或截断输入等基础编码行为。 |
| `tests/` | `test_signing.py`、`test_script.py` | 测试 BIP143/ECDSA 签名验证、脚本分类、data-push 和未知 opcode。 |
| `tests/` | `test_transaction_block.py` | 测试 legacy/SegWit 交易、合成区块、Merkle root 和逐字节无缺口覆盖。 |
| `data/` | `wallet_public.json` | 只保存 sender/receiver 公钥与 Testnet4 地址，不含私钥。 |
| `data/` | `transaction_draft.json`、`broadcast.json`、`confirmation.json` | 分别记录已签名交易草稿、广播结果和最终确认区块，保证各命令可续跑且不会重复生成密钥。 |
| `data/raw/` | `transaction.hex`、`block.hex`、`public_testnet4_block.hex` | 实验交易、包含实验交易的最终区块，以及前期集成测试区块的原始序列化字节；它们是解析器的唯一输入。 |
| `output/data/` | `generated_transaction.json`、`confirmed_transaction.json`、`confirmed_block.json`、`public_testnet4_block.json` | 可提交的交易/区块层级解析、哈希、金额、签名、Merkle root 和 PoW 验证结果。 |
| `output/data/` | `*_bytes.csv` | 逐字节覆盖表；每行含 offset、原始 hex、8-bit 二进制、字段路径、端序、解码值和说明。 |
| `output/pdf/` | `task1_testnet4_tx_block.pdf` | 最终课程提交版任务一报告。 |
| `report/` | `task1.tex`、`BUILD.md` | 中文 LaTeX 报告源文件，以及 XeLaTeX/`latexmk` 编译与 PDF 检查命令。 |
| `report/assets/` | `testnet4_*.png` | Faucet、广播、确认、余额和区块浏览器过程截图，仅包含公开链上信息。 |
| `.secrets/` | `testnet4_wallet.json` | 本机私钥文件，权限为 `0600`；被 `.gitignore` 忽略，绝不能作为交付物。 |
| `.venv/`、`tmp/`、`.pytest_cache/`、`__pycache__/`、`*.egg-info/` | 自动生成文件 | 分别是虚拟环境、LaTeX 构建/渲染缓存、测试缓存、Python 字节码和可编辑安装元数据；均可删除后重建，不属于课程交付物。 |

最终提交时，重点保留 `src/`、`tests/`、`data/` 中的公开实验状态、`output/data/`、`report/` 和 `output/pdf/`；提交前再次确认 `.secrets/` 未被打包。

## 安装

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

## 一次完整实验

```bash
.venv/bin/btc-lab wallet-init
.venv/bin/btc-lab funding-status
.venv/bin/btc-lab build --payment-sats 1000 --fee-rate 2
.venv/bin/btc-lab broadcast
.venv/bin/btc-lab fetch-confirmation
.venv/bin/btc-lab verify
```

如果交易持续未确认，可在确认它仍位于 mempool 后，用同一输入构造 opt-in RBF 替代交易：

```bash
.venv/bin/btc-lab build --payment-sats 1000 --fee-rate 10 --replace-draft
.venv/bin/btc-lab verify
.venv/bin/btc-lab broadcast
```

`wallet-init` 会打印发送地址与接收地址。请只向发送地址申请 Testnet4 faucet 资金，建议至少 5,000 sats。重复执行不会覆盖既有密钥。

## 解析独立数据

```bash
.venv/bin/btc-lab parse-tx --file data/raw/transaction.hex
.venv/bin/btc-lab parse-block --hash BLOCK_HASH
```

解析输出包含层级 JSON 和逐字节 CSV。CSV 中每一行恰好对应一个原始字节，并包含 offset、hex、8-bit 二进制、字段路径、端序和解释。

## 安全边界

- `.secrets/testnet4_wallet.json` 权限设置为 `0600`，不得提交或截图。
- `broadcast` 只接受本项目构造、且本地校验通过的 Testnet4 原始交易。
- 完整区块中的脚本会被反汇编；本项目完整执行和验证自己构造的 P2WPKH 输入，不试图替代 Bitcoin Core 的共识级 Script VM。

## 已验证公开结果

- 实验 TXID：`fda3dd67e4516d68c4f023a43c7a92629b9262d7e816d09cae873907c3666428`
- WTXID：`dbebb2a01ab826570124b004a33d6da4a14f552dfbb29323a7520d7a9f1d1fba`
- 确认高度：`144927`
- 区块哈希：`0000000000000000bb15b540dec2b41e6d2ce74775a6c90c6eaf307377309255`
- 完整区块：88,989 bytes、29 transactions、88,989/88,989 字节覆盖完整
- 验证：ECDSA、BIP143 sighash、TXID、WTXID、金额守恒、交易入块、Merkle root、PoW 均为 `true`
- 单元测试：17/17 通过
- 报告：`output/pdf/task1_testnet4_tx_block.pdf`
