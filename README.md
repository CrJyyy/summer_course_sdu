# 暑假实验课 — 项目总览

本仓库包含全同态密码与应用课程的实验作业：

---

## 目录结构

```
D:\Desktop\暑假实验课\
│
├── README.md                              # 本文件：项目总览与导航
│
└── experiment5_6_fhe_convolution/           # 全同态密码与应用 — 密文卷积实验
    ├── fhe_convolution.py                 # 主程序：FHE 卷积实现+旋转次数分析
    ├── requirements.txt                   # Python 依赖 (numpy, tenseal)
    └── README.md                          # 实验说明、原理与复现指南
```

---

## 实验导航

### 实验5&6: 全同态密文卷积

- **目录**: `experiment5_6_fhe_convolution/`
- **入口**: `python fhe_convolution.py`
- **内容**:
  - **作业5**: 使用 Microsoft SEAL (CKKS) 实现 4×4→2×2 密文卷积，验证正确性
  - **作业6**: 分析"打包→旋转→累加"策略的旋转次数是否达到理论最小值 (K²−1)

---

## 分工

| 姓名 | 学号 | 负责内容 |
|---|---|---|
| 朱仪烜 | 202300460031 | 作业5&6：全同态密文卷积实现、旋转次数理论分析、代码与文档 |

---

## 环境要求

- Python 3.8+
- numpy + tenseal (Microsoft SEAL Python 绑定)

---

## 快速开始

```bash
cd experiment5_6_fhe_convolution
pip install -r requirements.txt
python fhe_convolution.py
```
