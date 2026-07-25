# 《对称密码的软件实现与优化》86 页材料映射

原件：`对称密码的软件实现与优化.pptx`（SHA-256：
`69b70bead7ddf5feb3f12d582c5770c43241110eda6f45f9670cd4f18fc903cb`）。
项目副本与用户提供的原件逐字节一致。下表逐页说明材料内容在工程中的落点；
“实验/讨论”表示该页属于设计依据或平台边界，而不是声称存在同名生产后端。

| 页 | 材料主题 | 本项目落点 |
|---:|---|---|
| 1 | 标题 | `README.md`、中文报告封面 |
| 2 | 摘要与课程范围 | `README.md` 的覆盖矩阵 |
| 3 | CPU、寄存器、位宽与并行 | 报告“微架构基础” |
| 4 | 多发射与独立指令序列 | 报告关键路径讨论 |
| 5 | 执行端口、时延与吞吐 | 基准方法及报告 |
| 6 | Intel Skylake 端口 | x86 平台边界、待目标机实测 |
| 7 | AMD Zen 端口 | x86 平台边界、待目标机实测 |
| 8 | XOR/AND/查表/移位 | `src/aes.c`、`src/sm4.c`、`src/util.c` |
| 9 | 编译器与循环移位 | `sc_rotl32`、严格编译选项 |
| 10 | 大小端转换 | 显式 `load/store_be32/64` |
| 11 | 指令手册与新 ISA | `scripts/check_x86.sh` 反汇编闸门 |
| 12 | 布尔与算术操作 | 各标量轮函数 |
| 13 | 双目/三目指令差异 | 报告 ARM/x86 对照 |
| 14 | 移位 | SM4 线性层、GFNI 标量模型 |
| 15 | 内存寻址与数组 | T-table 实现及对象尺寸统计 |
| 16 | 表尺寸、寄存器、L1 | `table_sizes.csv`、结果讨论 |
| 17 | Skylake 缓存数据 | 报告引用为材料背景，不伪造本机数据 |
| 18 | Zen 缓存数据 | 报告引用为材料背景，不伪造本机数据 |
| 19 | 寄存器变量优于数组 | AES/SM4/TWINE 轮状态局部变量 |
| 20 | 全展开与指令缓存 | 报告代码尺寸权衡、`object_sizes.csv` |
| 21 | ballet 并行/依赖 | 报告算法依赖图讨论 |
| 22 | ballet 加解密差异 | 报告材料复述与边界 |
| 23 | ballet 关键路径 | 报告材料复述与边界 |
| 24 | Feistel 末置换消除 | TWINE/GIFT 表示讨论 |
| 25 | 输入输出节点对应 | 报告置换消除方法 |
| 26 | 变量重命名消除置换 | TWINE shuffle/fixslice 说明 |
| 27 | 周期后恢复顺序 | GIFT 4 路 bitslice、TWINE 轮置换 |
| 28 | SM4 优化路线 | `src/sm4.c` 三种表后端 |
| 29 | SM4 参考实现问题 | `sc_sm4_encrypt_ref` |
| 30 | 寄存器化与 XCHG 消除 | SM4 36 字滚动状态 |
| 31 | 代码规模与 256 B S 盒 | 对象/表尺寸 CSV |
| 32 | 4 KiB 四 T 表 | `SC_BACKEND_TTABLE` |
| 33 | S 盒与 T 表对比 | block 基准 CSV |
| 34 | 减少 T 表数量 | `SC_BACKEND_TTABLE_1K` |
| 35 | 单表加循环移位 | `round_t` 旋转路径 |
| 36 | 字节拆分与汇编 | 交叉编译与反汇编输出 |
| 37 | 1 KiB 表性能 | 原始/汇总基准结果 |
| 38 | 重叠读取构造 | `sm4_overlap[256][8]` |
| 39 | 非对齐读取 | 2 KiB 路径用显式大端加载避免 UB |
| 40 | T-table2 流程 | `SC_BACKEND_TTABLE_2K` |
| 41 | 256 B/4 KiB/1 KiB/2 KiB | `results/summary/table_sizes.csv` |
| 42 | 复杂算法关键路径 | 报告性能/代码尺寸权衡 |
| 43 | BMI 指令概览 | x86 ISA 讨论与平台边界 |
| 44 | PDEP/PEXT 与轻量线性层 | GIFT/TWINE bitslice/fixslice 讨论 |
| 45 | PDEP 语义 | 报告微架构章节 |
| 46 | PEXT 语义 | 报告微架构章节 |
| 47 | ARM 寄存器与三目操作 | ARM64 原生实现 |
| 48 | Cortex-A72/A76 | 报告跨微架构可移植性 |
| 49 | A78/A720/ARMv9 | 报告跨微架构可移植性 |
| 50 | X1/X925 | 报告跨微架构可移植性 |
| 51 | SIMD 与 shuffle | `src/arm64/shuffle_arm64.c` |
| 52 | SSE/AVX/NEON/SVE | ARM 原生、x86 交叉编译矩阵 |
| 53 | 批量 S 盒理想模型 | TWINE `TBL` 与 SM4 16 行 `TBL` |
| 54 | AVX2 gather | x86 ISA 见证；未伪造 M2 性能 |
| 55 | SSSE3 `PSHUFB` | `src/x86/isa_probes.c`、反汇编闸门 |
| 56 | 0–255 的 SIMD 查表 | SM4 固定 16 行 TBL 实现 |
| 57 | T 盒路线与安全问题 | README/报告 cache side-channel 警告 |
| 58 | 复合域与有限域求逆 | GFNI SM4 模型 |
| 59 | AES 有限域/仿射变换 | AES 标量 S 盒与报告 |
| 60 | AES x86/ARM 指令 | ARM `AESE/AESMC`、x86 `AESENC/VAES` |
| 61 | AES 指令流程 | `aes_arm64.c` 与反汇编 |
| 62 | AES 指令模拟 SM4 S 盒 | GFNI/AES 同构映射章节与 ISA 见证 |
| 63 | GF(2^8)↔GF((2^4)^2) | 报告复合域说明 |
| 64 | GF((2^4)^2) 求逆 | 报告复合域说明 |
| 65 | SM4 复合域矩阵合并 | `sc_sm4_gfni_scalar_model` |
| 66 | SM4 byteslice/AES-NI/bitslice/TBox | 后端覆盖矩阵 |
| 67 | SM4 8 路 T 盒步骤 | x86 AVX2 交叉编译设计说明 |
| 68 | unpack/矩阵转置 | 报告 SIMD 数据装配 |
| 69 | 4×4 矩阵转置 | 报告 SIMD 数据装配 |
| 70 | T 盒轮计算 | SM4 四表/单表/重叠表 |
| 71 | AVX2 8-way 完整流程 | x86 `VPSHUFB` 反汇编；待实机 |
| 72 | AVX2 16-way 寄存器权衡 | 报告 x86 平台边界 |
| 73 | 原材料 SM4 性能 | 仅作历史材料，不并入本机 CSV |
| 74 | AVX-512 | VAES/GFNI/VPCLMUL/VSM4 指令见证 |
| 75 | 大小核与 OpenMP | 报告未纳入稳态单核基准的原因 |
| 76 | ARM SM4/AES 指令 | NEON TBL、AESE；SM4E 编译/跳过 |
| 77 | TWINE 偶/奇支路 | `twine.c` 参考轮函数 |
| 78 | TWINE fixslicing/置换消除 | NEON `TBL` S 盒与轮置换 |
| 79 | GIFT fixslicing 文献 | `gift64.c` 四路 bitslice 表示 |
| 80 | GIFT-64 位切片 | 28 轮 bitslice 加/解密 |
| 81 | GIFT 四轮恢复位置 | 报告 fixslice 置换周期 |
| 82 | CTR、多路计数器与端序 | `sc_ctr_xor`，全部四类算法 |
| 83 | GCM | AES/SM4 GCM、PMULL GHASH、标签清零 |
| 84 | XTS | AES/SM4、CTS、IEEE/GB tweak 约定 |
| 85 | AVX-512/GFNI | GFNI 256 输入穷举、x86 指令见证 |
| 86 | 结束页 | 报告总结与平台边界 |

