# 对称密码的软件实现与优化

任务原文的逐项实现位置、核心函数和验证方法见
[`TASK_IMPLEMENTATION_MAP.md`](TASK_IMPLEMENTATION_MAP.md)。

这是一个独立的 C11 课程项目：从可审计的标量实现出发，比较
T-table、shuffle/fixslice、AES/PMULL/GFNI/SM4 等新指令，并把 AES、SM4、
GIFT-64、TWINE 接到 CTR/GCM/XTS 工作模式。原始 86 页 PPT 已原样保存在
`materials/`，逐页落点见 [`materials/SLIDE_MAP.md`](materials/SLIDE_MAP.md)。

> **实现边界：这是可复现实验实现，不是经过认证的生产密码库。** 本项目没有
> 经过商用密码检测、FIPS/GM/T 认证或独立侧信道审计。T-table 路径存在秘密
> 相关内存访问，选择该后端时必须同时评估吞吐率与缓存侧信道风险。

## 已实现范围

| 层次 | 覆盖 |
|---|---|
| 分组密码 | AES-128/192/256、SM4-128、GIFT-64/128-bit key、TWINE-80/128 |
| 参考实现 | 显式大端读写、加解密、原地操作、单块/多块统一接口 |
| T-table | AES 4 KiB；SM4 4 KiB、1 KiB+旋转、2 KiB 重叠读取 |
| Shuffle/fixslice | ARM NEON `TBL` 的 TWINE 4-bit S 盒/置换、SM4 固定 16 行 S 盒；GIFT 四路 bitslice |
| 新指令 | ARM `AESE/AESD`、`PMULL`、`TBL` 运行路径；x86 AES-NI/VAES/PSHUFB/GFNI/PCLMUL/VPCLMUL 已在 i9-13900H 原生执行；VSM4 已完成适配和静态指令检查，但实验设备不支持 |
| GFNI | 论文矩阵的标量模型，穷举验证全部 256 个 SM4 S 盒输入 |
| AES 辅助 SM4 | 常量访问预映射后用 AESE/AESENC 完成 S 盒，四块并行 |
| CTR | AES、SM4、GIFT-64、TWINE；大端计数器、尾部和回绕检测 |
| GCM | AES/SM4；96-bit IV 快速路径、任意 IV、AAD、PMULL GHASH、常量时间标签比较、失败清零 |
| XTS | AES/SM4；双密钥、CTS、IEEE 与 GB/T 17964 tweak 乘法；小于一块时拒绝 |
| 分派 | `auto/ref/ttable-4k/ttable-1k/ttable-2k/shuffle/aes-hw/gfni/sm4-hw` |

GCM/XTS 只接受 128-bit 分组的 AES/SM4；GIFT-64 与 TWINE 只接 CTR。
Apple M2 Pro 与本次 x86 主机都不提供 SM4 专用指令，`sm4-hw` 会返回“不支持”，
而不是悄悄伪装成硬件结果。ARM SM4E 和 Intel VSM4 均已完成后端适配与
静态指令检查，但现有设备无法提供相应的原生性能数据；其余 x86 后端已完成
原生正确性和性能验证。

## 一键复现

```sh
cd experiment_3_symmetric_cipher
make test            # KAT、随机/边界测试、OpenSSL 3.6+ 差分
make test-sanitize   # ASan + UBSan
make check-x86       # x86 交叉编译、ARM/x86 指令反汇编闸门
make validate-x86    # x86 真机测试、sanitizer、反汇编、基准和状态文件
make bench           # 3 次预热、15 次采样、CSV/JSON
make report          # 图表、中文 LaTeX、最终 PDF
make all             # 以上全部
```

OpenSSL 优先通过 `pkg-config` 定位；没有 `pkg-config` 时回退到
`/opt/homebrew/opt/openssl@3`，也可用 `OPENSSL_PREFIX` 覆盖。编译默认启用
`-Wall -Wextra -Wpedantic -Werror`。Windows 原生验证使用 MSYS2 UCRT64
Clang/LLVM/OpenSSL；sanitizer 使用官方 LLVM Windows 运行库。

命令行后端选择示例：

```sh
make build/sc_demo
./build/sc_demo aes128 aes-hw \
  000102030405060708090a0b0c0d0e0f \
  00112233445566778899aabbccddeeff
```

## 验证证据

- `tests/test_symcrypto.c`：官方/论文 KAT、RFC 8998 SM4-GCM、多块/非对齐/
  原地/回绕边界、固定种子随机交叉比较及 256 输入 GFNI 模型验证。
- `tests/test_x86_backends.c`：直接执行 AES-NI/VAES、SSSE3、GFNI、
  AES-assisted SM4、PCLMUL/VPCLMUL，并分别与参考实现比较。
- `tests/test_openssl_diff.c`：AES/SM4 的 ECB、CTR、GCM、XTS 随机差分；
  AES-XTS 还比较 63-byte CTS。
- `build/x86/runtime.disasm`：由 `check-x86` 生成并检查实际后端中的
  `AESENC/AESDEC/VAESENC/VAESDEC/PSHUFB/PCLMULQDQ/VPCLMULQDQ/`
  `GF2P8AFFINEINV/VSM4RNDS4/VSM4KEY4`；独立 ISA 探针补充检查
  `VPSHUFB` 与 ARM `PMULL`，ARM 实际后端同时检查
  `AESE/AESD/TBL/SM4E/SM4EKEY`。
- `results/raw/native_samples.csv`：每个正式样本；不只保存汇总数。
- `results/summary/native_summary.json`：median、Q1/Q3、IQR、GB/s、ns/byte。
- `results/raw/x86_samples.csv` 与 `results/summary/x86_summary.json`：3240 个
  x86 原始样本、216 条汇总，以及每条样本的 RDTSCP TSC ticks/byte。
- `results/summary/x86_status.json`：CPU 特征、测试计数、ISA 原生执行状态和
  VSM4 后端的适配与静态指令证据。
- `results/summary/object_sizes.csv` 与 `table_sizes.csv`：对象和表尺寸。
- `output/pdf/symmetric_cipher_software_optimization.pdf`：中文完整报告。

## 目录

```text
include/            公共 API
src/                算法、模式、分派与 ISA 后端
tests/              KAT、随机/边界、OpenSSL 差分
bench/              六档消息长度基准
scripts/            ISA 检查、绘图、报告构建
materials/          原始 PPT 与 86 页映射
results/raw/        ARM/x86 逐样本 CSV
results/summary/    ARM/x86 机器可读汇总、验收状态与尺寸
results/figures/    从 JSON 生成的 PDF/PNG 图
report/             中文 LaTeX 源码
output/pdf/         最终 PDF
```

## 实现边界

- ARM64 数据来自 Apple M2 Pro；x86 数据来自 Windows x86-64 上的
  Intel Core i9-13900H。两组数据分开保存，不脱离平台直接比较。
- i9-13900H 原生执行 AES-NI、VAES、SSSE3、GFNI、PCLMUL 和 VPCLMUL。
  VSM4 后端已完成适配和编译/反汇编检查，但该处理器未报告 VSM4 支持，
  因此没有 VSM4 原生执行与性能结果。
- x86 的 `cycles_per_byte` 字段实际表示序列化 RDTSCP 得到的 invariant-TSC
  ticks/byte，不等同于随睿频变化的物理核心时钟周期。
- NEON/SSSE3 SM4 shuffle 固定扫描 16 行 S 盒，并以四块并行摊薄装配开销；
  其价值仍是对照“常量时间”和“最高吞吐”不是同一目标。
- CTR 八路生成计数器，GCM 四块聚合 GHASH，XTS 八路生成 tweak；回绕在写
  输出前预检，XTS-CTS 支持原地操作。
- 基准排除密钥扩展；模式开销、计数器/tweak 生成和 GCM 标签计算计入。

标准依据：[FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)、
[GB/T 32907-2016](https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=7803DE42D3BC5E80B0C3E5D8E873D56A)、
[NIST SP 800-38 系列](https://csrc.nist.gov/projects/block-cipher-techniques/bcm)、
[RFC 8998](https://www.rfc-editor.org/rfc/rfc8998.html)。
