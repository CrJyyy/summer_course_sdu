# SM3软件实现与优化

> **Target Architectures**: x86-64 (AVX2 / AVX512) & ARM64 (NEON + GPR) 
> **Optimization Strategy**: SIMD-GPR Hybrid

---

## 项目简介

本项目实现了国密算法 **SM3** 的多种版本，包括标准参考实现（Baseline）、x86-64 SIMD+GPR 混合优化实现（AVX2/AVX512）以及 ARM64 SIMD+GPR 混合优化实现（NEON）。

核心优化思路：SIMD 寄存器负责高吞吐的消息加载、字节序转换与无依赖的并行异或；通用寄存器（GPR）负责存在严格数据依赖链的迭代压缩。通过 64 轮全展开消除分支与字置换开销。

---

## 目录结构

```text
.
├── code/
│   └── sm3.c          	 # 标准 C 实现（对照组）
│   └── sm3_x86.c               # x86-64 优化实现（AVX2 / AVX512 / Scalar 三路径）
│   └── sm3_arm64.c             # ARM64 优化实现（NEON + GPR On-the-fly）
├── README.md                   # 项目简介与快速开始
└── SM3_REPORT.md                   # 完整报告
```

| 文件 | 作用 | 关键技术 |
|------|------|----------|
| `code/sm3.c` | 未优化的标准实现 | 纯 C、循环 64 轮、完整计算 `W[68]` 与 `W′[64]` 到栈内存 |
| `code/sm3_x86.c` | x86-64 混合优化 | AVX2/AVX512 `vpshufb` 宽位加载与字节序转换、向量化 `W′` 异或、GPR 64 轮全展开、运行时 `cpuid` 分发 |
| `code/sm3_arm64.c` | ARM64 混合优化 | NEON `vld1q_u8` + `vrev32q_u8` 加载与字节逆序、16 字滑动窗口 `r[16]`、On-the-fly 消息扩展与压缩交错、64 轮全展开宏 |

---
##  测试环境
| 架构 | CPU | 编译器 | 操作系统 |
|------|-----|------|--------|
| x86-64 | AMD Ryzen 9 7945HX | GCC 11.4 | Ubuntu 22.04 |
| ARM64 | Apple M2 Pro|Apple clang 17.0.0| macOS 15.6.1|

---
## 编译命令


### 1. x86-64 架构 (Intel/AMD)

**Linux (GCC)**：

```bash
#标准sm3编译与运行
gcc -O3 -march=native sm3.c -o sm3
./sm3

# 开启 AVX2, AVX512 相关扩展支持
gcc -O3 -mavx2 -mavx512f -mavx512bw sm3_x86.c -o sm3_x86
./sm3_x86
```

**Windows (MSVC on Visual Studio)**：

- 建议将项目 C/C++ 语言标准设置为 **ISO C11 Standard**。
- 保持代码中的 `alignas` 语法，无需在项目属性中强制全局开启 `/arch:AVX512`。

### 2. ARM64 架构

**Linux / macOS (Clang or GCC)**：

```bash
# 开启 NEON 向量引擎及寄存器流水线优化(Linux)
gcc -O3 -march=armv8-a sm3_arm64.c -o sm3_arm64
./sm3_arm64

#macOS
clang -O3 -o sm3_arm64 sm3_arm64.c
```

---

## 4. 正确性验证

所有版本均通过 SM3 标准测试向量 `abc` 验证：

| 输入 | 预期哈希（GM/T 0004-2012） |
|------|--------------------------|
| `abc` | `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0` |

---

## 5. 实验结果

> **测试方法**：处理 100 MB（10 MB × 10 次）数据，取平均吞吐量。

| 架构 | 实现版本 | 吞吐量 (MB/s) |
|------|----------|---------------|
| **x86-64** | Baseline (Scalar) | ~386 |
| **x86-64** | AVX2 Hybrid | ~433 |
| **x86-64** | AVX512 Hybrid | ~440 |
| **ARM64** | Baseline (Scalar) | ~163 |
| **ARM64** | NEON+GPR Hybrid | ~252 |

> **注**：若 x86 虚拟机未暴露 AVX2/AVX512，程序将自动回退到 Scalar 路径。详见 `SM3_REPORT.md` 的“已知问题”章节。

---

## 6. 详细报告

完整的技术原理、架构级优化与详细数据分析，请参阅：

**[SM3_REPORT.md](SM3_REPORT.md)**
