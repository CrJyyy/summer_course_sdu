# 全同态密码与应用 — 作业5 & 作业6

## 依赖环境

- Python 3.8+
- Windows / Linux / macOS

### 安装依赖

```bash
pip install -r requirements.txt
```

> **注意**: `tenseal` 包自带 MSVC 运行时，Windows 用户无需额外安装 SEAL C++ 库。

### requirements.txt 内容

```
numpy>=1.20.0
tenseal>=0.3.0
```

---

## 快速复现

### 1. 安装依赖

```bash
cd experiment5_6_fhe_convolution
pip install -r requirements.txt
```

### 2. 运行实验

```bash
python fhe_convolution.py
```

### 3. 预期输出

程序将依次执行以下步骤并打印结果：

| 步骤 | 内容 |
|---|---|
| 环境初始化 | 打印 CKKS 参数 (polynomial modulus degree, coeff modulus, slot count, scale) |
| 明文卷积 | 计算 4×4 输入与 3×3 Sobel 核的 2D 卷积作为基准 |
| 密文打包 | 将输入矩阵按行主序编码加密到单个密文中 |
| 旋转+累加 | 遍历卷积核位置，旋转→乘权值→累加，打印每次旋转详情 |
| 结果验证 | 对比明文与密文输出，打印误差 |
| 理论分析 | 旋转次数是否达到理论最小值 (K²-1) |

**预期密文输出 (2×2):**

```
[[ 4.0, 15.0],
 [ 8.0,  9.0]]
```

CKKS 近似误差 < 1e-5。

---

## 文件说明

| 文件 | 作用 |
|---|---|
| `fhe_convolution.py` | 主程序：FHE 环境初始化、密文卷积实现、正确性验证、旋转次数理论分析 |
| `requirements.txt` | Python 依赖列表 (numpy + tenseal) |
| `README.md` | 本文件：实验说明与复现指南 |

---

## 算法原理

### 作业5: 密文卷积实现

**策略**: 打包 → 旋转 → 累加 (Pack → Rotate → Accumulate)

```
输入: 4×4 矩阵 (16 个元素)
卷积核: 3×3 (9 个权值)
步长 = 1, 无填充 → 输出: 2×2

Step 1 - 打包 (Pack):
  将 4×4 输入按行主序 (row-major) 编码到 CKKS 密文的 16 个 slot 中:
  slot: [0,1,2,3, 4,5,6,7, 8,9,10,11, 12,13,14,15]

Step 2 - 旋转 (Rotate):
  对每个卷积核位置 (kr, kc)，将密文左旋转 d = kr×4 + kc 步
  旋转后, slot[j] = 原始 input[j + d]

Step 3 - 累加 (Accumulate):
  旋转后密文 × kernel[kr, kc] → 累加到结果密文
  最终 slot[j] = Σ_{kr,kc} input[j+kr×4+kc] × kernel[kr, kc]

Step 4 - 提取输出:
  有效卷积输出位于 slot 0, 1, 4, 5 (对应 2×2 输出矩阵)
```

**库选择**: Microsoft SEAL (通过 TenSEAL 的 `sealapi` 底层 C++ bindings)

**方案**: CKKS (支持浮点近似运算)

**关键技术细节**:
- 使用 `tenseal.sealapi` 底层 API 直接调用 SEAL 的 `Evaluator::rotate_vector` 实现密文旋转
- Galois 密钥预生成所有需要的旋转步长
- 对零权值位置跳过旋转和乘法 (避免 CKKS 中零明文导致透明密文)

### 作业6: 旋转次数理论分析

**问题**: "打包→旋转→累加"策略下, 旋转次数是否达到理论最小值?

**不同旋转量**: {0, 1, 2, 4, 5, 6, 8, 9, 10} — 共 9 个 (含 d=0)

**分析**:

1. **密集卷积核** (所有权值非零): 理论最小值 = K²-1 = 8 次
   - 每个不同旋转量至少需要一次 `rotate_vector` 操作
   - 二进制分解法 (先算 1,2,4,8 再组合 5,6,9,10) 仍需要 8 次
   - **无法做到更少**

2. **稀疏卷积核** (有权值为零): 有效最小值 = 非零权值数 - 1
   - 本次 Sobel-like 核有 6 个非零权值, 仅需 5 次旋转

3. **特殊情况可进一步减少**:
   - 卷积核可分离 (separable): 3×3 → 3×1 + 1×3, 仅需 2+2 = 4 次
   - 输出空间旋转策略
   - 不同的输入打包方式 (交错打包、channel packing 等)

**结论**: 对于一般密集 3×3 核, 8 次即为理论最小值; 本次因核稀疏仅需 5 次.
