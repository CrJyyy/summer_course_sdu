# Bitcoin 实验一

本目录包含课程实验的两个独立任务：

- `01_testnet4_tx_block`：Testnet4 P2WPKH 交易构造、广播、逐字节交易/区块解析与实验报告。
- `02_secp256k1_report`：libsecp256k1 安全修复、性能优化、数学原理与可复现实验报告。

## 推荐执行顺序

```bash
cd 01_testnet4_tx_block
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/btc-lab wallet-init
.venv/bin/btc-lab funding-status

# faucet 到账后
.venv/bin/btc-lab build
.venv/bin/btc-lab broadcast
.venv/bin/btc-lab fetch-confirmation
.venv/bin/btc-lab verify

cd ../02_secp256k1_report
python3 scripts/reproduce.py --help
```

Testnet4 faucet 只发送没有现实价值的测试币。任务一生成的私钥位于本地 `.secrets/`，已被忽略，任何报告和公开数据中均不得包含私钥。

## 当前状态

- 软件、17 个单元测试、两份 LaTeX 报告和 PDF：已完成并验证。
- 真实实验交易 TXID：
  `fda3dd67e4516d68c4f023a43c7a92629b9262d7e816d09cae873907c3666428`；
  付款 1,000 sats、手续费 282 sats、141 vB，已确认。
- 包含实验交易的 Testnet4 区块：高度 `144927`，区块哈希
  `0000000000000000bb15b540dec2b41e6d2ce74775a6c90c6eaf307377309255`；
  本地验证 88,989/88,989 字节覆盖、交易入块、Merkle root 与 PoW。
- Testnet4 一次性发送地址见
  `01_testnet4_tx_block/data/wallet_public.json`；私钥只保存在权限为
  `0600` 的被忽略文件中。
- ECDSA 签名、BIP143 sighash、TXID、WTXID、金额守恒和全部区块检查均为 `true`。

## 最终 PDF

- `01_testnet4_tx_block/output/pdf/task1_testnet4_tx_block.pdf`
- `02_secp256k1_report/output/pdf/task2_secp256k1_report.pdf`
