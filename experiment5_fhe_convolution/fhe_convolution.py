"""
================================================================================
全同态密码与应用 — 作业5 & 作业6
================================================================================

作业5: 使用开源全同态加密库 (Microsoft SEAL / TenSEAL)，实现密文卷积。
       输入: 4×4 单通道矩阵
       卷积核: 3×3
       步长: 1, 无填充 (VALID padding)
       输出: 2×2 矩阵

作业6: 采用"打包→旋转→累加"策略，分析旋转次数是否达到理论最小值。

策略说明:
  1. 打包 (Pack):   将 4×4 输入矩阵按行主序 (row-major) 编码到单个密文中
  2. 旋转 (Rotate): 对每个卷积核位置 (kr, kc)，将密文旋转 kr×W+kc 步
  3. 累加 (Accumulate): 将旋转后的密文乘以对应权值，累加得到卷积结果

库: Microsoft SEAL (via TenSEAL sealapi 底层 C++ 绑定)
方案: CKKS (全同态加密，支持近似浮点运算)
"""

import numpy as np
from tenseal.sealapi import (
    Evaluator, CKKSEncoder, KeyGenerator, Encryptor, Decryptor,
    SEALContext, EncryptionParameters, SCHEME_TYPE, CoeffModulus,
    SEC_LEVEL_TYPE, Ciphertext, Plaintext, PublicKey, GaloisKeys
)


# ============================================================================
# 1. FHE 环境初始化
# ============================================================================

def setup_fhe(poly_modulus_degree=8192, coeff_mod_bit_sizes=None):
    """
    创建 CKKS 同态加密上下文，生成密钥。

    Returns:
        encoder, encryptor, evaluator, decryptor, galois_keys, scale, context
    """
    if coeff_mod_bit_sizes is None:
        # 2 个中间素数 → 支持 1 层乘法深度
        coeff_mod_bit_sizes = [60, 40, 40, 60]

    parms = EncryptionParameters(SCHEME_TYPE.CKKS)
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(
        CoeffModulus.Create(poly_modulus_degree, coeff_mod_bit_sizes)
    )

    ctx = SEALContext(parms, True, SEC_LEVEL_TYPE.TC128)

    # 密钥生成
    keygen = KeyGenerator(ctx)
    secret_key = keygen.secret_key()

    pk = PublicKey()
    keygen.create_public_key(pk)

    # Galois 密钥 (用于密文旋转)
    gk = GaloisKeys()
    keygen.create_galois_keys(gk)

    # 各组件
    encoder = CKKSEncoder(ctx)
    encryptor = Encryptor(ctx, pk, secret_key)
    evaluator = Evaluator(ctx)
    decryptor = Decryptor(ctx, secret_key)

    scale = pow(2.0, 40)

    print(f"[FHE 环境] 多项式模数度: {poly_modulus_degree}")
    print(f"[FHE 环境] 系数模数位宽: {coeff_mod_bit_sizes}")
    print(f"[FHE 环境] CKKS 槽数: {encoder.slot_count()}")
    print(f"[FHE 环境] 全局缩放因子: 2^{40:.0f}")

    return encoder, encryptor, evaluator, decryptor, gk, scale, ctx


# ============================================================================
# 2. 明文卷积 (基准验证)
# ============================================================================

def plain_conv2d(input_matrix, kernel):
    """
    明文 2D 卷积 (VALID 模式, 步长=1, 无填充)

    Args:
        input_matrix: H×W 输入矩阵
        kernel: K×K 卷积核

    Returns:
        (H-K+1)×(W-K+1) 输出矩阵
    """
    H, W = input_matrix.shape
    K = kernel.shape[0]
    out_H = H - K + 1
    out_W = W - K + 1
    output = np.zeros((out_H, out_W))

    for i in range(out_H):
        for j in range(out_W):
            output[i, j] = np.sum(input_matrix[i:i+K, j:j+K] * kernel)

    return output


# ============================================================================
# 3. 密文卷积: "打包 → 旋转 → 累加" 策略
# ============================================================================

def fhe_conv2d_pack_rotate_accumulate(
    encoder, encryptor, evaluator, decryptor, gk, scale, ctx, input_matrix, kernel
):
    """
    使用"打包→旋转→累加"策略实现密文 2D 卷积。

    算法:
      For each kernel position (kr, kc):
        1. 旋转输入密文 (左旋转 kr*W + kc 步)
        2. 乘以 kernel[kr, kc]
        3. 累加到结果密文

    结果密文的 slot j 包含:
      sum_{kr,kc} input[j + kr*W + kc] * kernel[kr, kc]

    有效输出位于 slot {0, 1, 4, 5} (对应 2×2 输出矩阵的行主序索引).

    Returns:
        result_ct: 密文结果
        rotation_count: 旋转操作次数
        rotation_details: 每次旋转的详细信息
    """
    H, W = input_matrix.shape  # 4, 4
    K = kernel.shape[0]        # 3
    N = H * W                  # 16

    # --- Step 1: 打包 (Pack) ---
    # 将 4×4 输入按行主序扁平化为 16 维向量，编码并加密
    input_flat = input_matrix.flatten().astype(np.float64).tolist()

    pt_input = Plaintext()
    encoder.encode(input_flat, scale, pt_input)

    ct_input = Ciphertext(ctx)
    encryptor.encrypt(pt_input, ct_input)
    print(f"\n[打包] 输入矩阵 {H}×{W} 已编码为 {N} 维向量并加密")

    # --- Step 2 & 3: 旋转 (Rotate) + 累加 (Accumulate) ---
    rotation_count = 0
    rotation_details = []
    ct_result = None  # 累加器, 将在首个非零权值项后初始化

    # 遍历每个卷积核位置
    for kr in range(K):
        for kc in range(K):
            rot_amount = kr * W + kc   # 旋转量
            weight = float(kernel[kr, kc])

            # 零权值: 跳过 (避免 CKKS 中零明文导致透明密文)
            if abs(weight) < 1e-12:
                rotation_details.append(
                    f"kernel[{kr},{kc}]={weight:+5.1f}  |  "
                    f"旋转量={rot_amount:2d}  |  跳过 (权值为零)"
                )
                continue

            if rot_amount == 0:
                # 无需旋转
                ct_rotated = ct_input
                rot_detail = "无旋转"
            else:
                # 左旋转 rot_amount 步
                ct_rotated = Ciphertext(ctx)
                evaluator.rotate_vector(ct_input, rot_amount, gk, ct_rotated)
                rotation_count += 1
                rot_detail = f"左旋转 {rot_amount} 步"

            # 乘以卷积核权值
            pt_weight = Plaintext()
            encoder.encode([weight] * N, scale, pt_weight)

            ct_product = Ciphertext(ctx)
            evaluator.multiply_plain(ct_rotated, pt_weight, ct_product)
            evaluator.rescale_to_next_inplace(ct_product)

            # 累加
            if ct_result is None:
                ct_result = ct_product  # 第一个非零 product 作为初始值
            else:
                evaluator.add_inplace(ct_result, ct_product)

            rotation_details.append(
                f"kernel[{kr},{kc}]={weight:+5.1f}  |  "
                f"旋转量={rot_amount:2d}  |  {rot_detail}"
            )

    print(f"[旋转] 共执行 {rotation_count} 次旋转操作")
    print(f"[累加] 9 个 (旋转×权值) 项已累加完成")

    # --- Step 4: 解密并提取有效输出区域 ---
    pt_result = Plaintext()
    decryptor.decrypt(ct_result, pt_result)
    full_result = np.array(encoder.decode_double(pt_result))

    # 提取有效输出 (前 16 个 slot 中对应 2×2 输出的位置)
    out_H = H - K + 1  # 2
    out_W = W - K + 1  # 2

    output = np.zeros((out_H, out_W))
    for i in range(out_H):
        for j in range(out_W):
            slot_idx = i * W + j  # 0, 1, 4, 5
            output[i, j] = full_result[slot_idx]

    return output, full_result[:N], rotation_count, rotation_details


# ============================================================================
# 4. 主程序
# ============================================================================

def main():
    print("=" * 72)
    print("  全同态密码与应用 — 作业5 & 作业6")
    print("  密文卷积: 4×4 输入, 3×3 卷积核, 步长=1, 无填充")
    print("=" * 72)

    # --- 定义输入和卷积核 ---
    np.random.seed(42)
    input_matrix = np.random.randint(1, 10, (4, 4)).astype(np.float64)

    # Sobel-X 类边缘检测卷积核
    kernel = np.array([
        [-1,  0,  1],
        [-2,  0,  2],
        [-1,  0,  1]
    ], dtype=np.float64)

    print(f"\n{'─' * 72}")
    print(f"  输入矩阵 (4×4):")
    print(f"{'─' * 72}")
    for row in input_matrix:
        print(f"  {row}")
    print()

    print(f"{'─' * 72}")
    print(f"  卷积核 (3×3):")
    print(f"{'─' * 72}")
    for row in kernel:
        print(f"  {row}")

    # --- 明文卷积 (基准) ---
    plain_output = plain_conv2d(input_matrix, kernel)
    print(f"\n{'─' * 72}")
    print(f"  明文卷积结果 (2×2) — 基准:")
    print(f"{'─' * 72}")
    for row in plain_output:
        print(f"  {row}")
    print(f"\n  明文输出 (展平): {plain_output.flatten()}")

    # --- 密文卷积 ---
    print(f"\n{'=' * 72}")
    print(f"  初始化 FHE 环境...")
    print(f"{'=' * 72}")
    encoder, encryptor, evaluator, decryptor, gk, scale, ctx = setup_fhe()

    print(f"\n{'=' * 72}")
    print(f"  执行密文卷积 (打包 → 旋转 → 累加)")
    print(f"{'=' * 72}")

    fhe_output, full_vector, rotation_count, rotation_details = \
        fhe_conv2d_pack_rotate_accumulate(
            encoder, encryptor, evaluator, decryptor, gk,
            scale, ctx, input_matrix, kernel
        )

    # --- 详细输出 ---
    print(f"\n{'─' * 72}")
    print(f"  旋转操作详情:")
    print(f"{'─' * 72}")
    for detail in rotation_details:
        print(f"  {detail}")

    print(f"\n{'─' * 72}")
    print(f"  密文解密全向量 (前 16 个 slot):")
    print(f"{'─' * 72}")
    print(f"  {np.round(full_vector, 6)}")
    print(f"\n  有效输出位置标记:")
    print(f"  slot  0  ← output[0,0]")
    print(f"  slot  1  ← output[0,1]")
    print(f"  slot  4  ← output[1,0]")
    print(f"  slot  5  ← output[1,1]")

    # --- 正确性验证 ---
    print(f"\n{'=' * 72}")
    print(f"  作业5: 正确性验证")
    print(f"{'=' * 72}")

    print(f"\n  明文卷积结果 (2×2):")
    for row in plain_output:
        print(f"  {row}")

    print(f"\n  密文卷积结果 (2×2):")
    for row in fhe_output:
        print(f"  {row}")

    error = np.abs(fhe_output - plain_output)
    max_error = np.max(error)
    mean_error = np.mean(error)

    print(f"\n  逐元素绝对误差:")
    for row in error:
        print(f"  {row}")

    print(f"\n  最大绝对误差: {max_error:.2e}")
    print(f"  平均绝对误差: {mean_error:.2e}")

    if max_error < 1e-6:
        print(f"\n  [OK] 验证通过! 密文卷积结果与明文一致。")
    elif max_error < 1e-3:
        print(f"\n  [OK] 验证通过! (CKKS 近似误差在合理范围内 < 1e-3)")
    else:
        print(f"\n  [FAIL] 验证失败! 误差过大，请检查参数。")

    # --- 作业6: 旋转次数理论分析 ---
    print(f"\n{'=' * 72}")
    print(f"  作业6: 旋转次数理论最小值分析")
    print(f"{'=' * 72}")

    K = 3           # 卷积核大小
    W_val = 4       # 输入宽度
    theoretical_min_dense = K * K - 1  # 一般密集卷积核: K^2-1

    # 统计非零权值数量
    nonzero_count = int(np.sum(np.abs(kernel) > 1e-12))
    theoretical_min_sparse = nonzero_count - 1  # 稀疏核: 非零权值数-1 (减去(0,0)位置)

    # 计算所有不同的旋转量
    distinct_rotations = set()
    for kr in range(K):
        for kc in range(K):
            distinct_rotations.add(kr * W_val + kc)

    print(f"""
  问题设定:
    - 输入: {W_val}x{W_val} 矩阵 (按行主序打包, 共 {W_val*W_val} 个 slot)
    - 卷积核: {K}x{K} (共 {K*K} 个权值位置, 其中 {nonzero_count} 个非零)
    - 策略: "打包 -> 旋转 -> 累加"

  分析:

  1. 每个卷积核位置 (kr, kc) 对应唯一的旋转量 d = kr×W + kc:
     旋转量集合 = {sorted(distinct_rotations)}
     共 {len(distinct_rotations)} 个不同旋转量 (含旋转量 0)

  2. 对于一般密集卷积核 (所有权值非零):
     - 旋转量 0 无需实际操作
     - 其余 {len(distinct_rotations)-1} 个旋转量各需一次旋转
     - 理论最小值: K^2 - 1 = {theoretical_min_dense} 次旋转

  3. 是否可以比 K^2-1 更少?

     a) 二进制分解法:
        先计算步长为 1,2,4,8 的旋转 (4 次),
        再通过组合得到 5=1+4, 6=2+4, 9=1+8, 10=2+8 (4 次),
        仍需要 8 次旋转操作 (每个组合产生一个新密文).

        -> 结论: 无法减少。每个不同的非零旋转量至少需要一个
           旋转操作来产生对应的密文。

     b) 特殊情况可减少旋转:
        - 卷积核稀疏 (权值为零): 零权值位置无需旋转, 对
          本次 Sobel-like 核 (6 个非零权值), 仅需 5 次旋转
        - 卷积核可分离 (separable): 3x3 -> 3x1 + 1x3,
          仅需 2+2 = 4 次旋转
        - 使用不同的打包策略 (如 channel packing)

  4. 本次实验结果:
""")
    print(f"     一般密集核理论最小值:  K^2-1 = {theoretical_min_dense}")
    print(f"     本次稀疏核有效最小值:  非零权值-1 = {theoretical_min_sparse}")
    print(f"     实际执行旋转次数:      {rotation_count}")
    print(f"     是否达到(稀疏核)理论最小值: {'是 [OK]' if rotation_count <= theoretical_min_sparse else '否'}")
    print(f"     是否达到(密集核)理论最小值: {'是 [OK]' if rotation_count == theoretical_min_dense else f'否 (本次仅需{rotation_count}次, 因核中有{K*K-nonzero_count}个零权值)'}")

    # 详细分析表格
    print(f"\n  {'─' * 72}")
    print(f"  卷积核位置 -> 旋转量 对照表:")
    print(f"  {'─' * 72}")
    print(f"  {'kr':>3} {'kc':>3} | {'权值':>6} | {'旋转量 d=kr*W+kc':>18} | {'说明'}")
    print(f"  {'─'*3} {'─'*3}─┼─{'─'*6}─┼─{'─'*18}─┼─{'─'*30}")
    for kr in range(K):
        for kc in range(K):
            d = kr * W_val + kc
            w = float(kernel[kr, kc])
            if d == 0:
                note = "无旋转 (d=0)"
            elif abs(w) < 1e-12:
                note = "跳过 (权值为零)"
            else:
                note = f"需旋转 {d} 步"
            print(f"  {kr:>3} {kc:>3} | {w:>+6.1f} | {d:>18} | {note}")
    print(f"  {'─' * 72}")

    print(f"""
  最终结论:
    - "打包->旋转->累加"策略下, 对于一般 {K}x{K} 卷积核,
      旋转次数的理论最小值为 K^2-1 = {theoretical_min_dense} 次.
    - 本次实验中, 由于使用了稀疏卷积核 (Sobel-like, {nonzero_count} 个
      非零权值), 实际仅需 {rotation_count} 次旋转.
    - 对于密集卷积核, 该策略恰好达到理论最小值 (无法做到更少).
    - 若要进一步减少旋转次数, 需使用:
      (a) 卷积核分离 (decomposable kernel)
      (b) 输出空间旋转 (output stationary rotation)
      (c) 不同的打包策略 (如稀疏打包、交错打包等)
""")

    print("=" * 72)
    print("  实验完成!")
    print("=" * 72)


if __name__ == "__main__":
    main()
