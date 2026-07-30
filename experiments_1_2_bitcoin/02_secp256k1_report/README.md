# Task 2 - libsecp256k1 security and performance study

本任务研究 Bitcoin Core 的 `libsecp256k1`，聚焦编译器引入的 constant-time 安全回归与固定基点乘法性能优化。

## 目录与主要文件

```text
02_secp256k1_report/
├── scripts/           # 一键复现脚本
├── data/              # 上游研究案例清单
├── results/           # 可提交的原始证据、测量值和统计结果
├── report/            # LaTeX 报告源文件与编译说明
├── output/pdf/        # 最终课程报告 PDF 与同内容 Markdown
├── work/              # 下载的上游源码和本机构建树
├── .venv/             # Python/CMake/Ninja 虚拟环境
├── tmp/               # LaTeX 临时文件和逐页渲染结果
├── .gitignore         # 排除可重建的大型目录和临时文件
└── README.md          # 本说明文件
```

各目录中的主要文件及用途如下。

| 路径 | 主要文件 | 用途 |
|---|---|---|
| `scripts/` | `reproduce.py` | 一键获取固定标签、记录 commit 和源码差异、用 Clang Release 构建、运行官方测试/benchmark，并生成环境、统计和库大小结果。`--case sizes` 可只重建库大小 CSV/JSON。 |
| `scripts/` | `forge_digest_demo.py` | 只使用公开压缩公钥和攻击者选择的 `u,v`，复现“验证器信任外部摘要”时的 ECDSA 存在性伪造，并对固定消息给出失败对照。 |
| `data/` | `upstream_cases.csv` | 固定两个安全案例和两个性能案例的版本、日期、上游结论及本机验证边界，是报告选题与复现范围的输入清单。 |
| `results/` | `environment.json` | 保存 CPU、操作系统、架构、编译器、CMake、Python 等实验环境，支持结果复核。 |
| `results/` | `tag_commits.csv`/`.json`、`case_commits.json`、`build_matrix.json` | 固定 release tag 与 commit 的对应关系、案例提交证据，以及每个版本/预计算表配置的构建和测试状态。 |
| `results/` | `benchmark_runs.csv` | 保存四组配置每次正式 benchmark 的原始结构化测量值；预热不混入统计样本。 |
| `results/` | `benchmark_summary.csv`/`.json`、`analysis_summary.json` | 从逐次数据计算 median、IQR、ops/s 和跨配置比较，供 LaTeX 报告引用。 |
| `results/` | `library_sizes.csv`/`.json` | 由 `reproduce.py` 自动定位真实动态库 artifact 并生成的文件大小、构建版本和预计算表配置。 |
| `results/` | `forgery_demo.json` | 摘要伪造复现实验的公开公钥、攻击者输入、构造出的 `(r,s,e)` 以及“选择摘要成功、固定消息失败”的布尔结果。 |
| `results/raw/` | `configure_*.txt`、`build_*.txt`、`ctest_*.txt`、`bench_*.txt` | 保存每种版本和表大小的配置、编译、官方测试与 10 次 benchmark 原始终端输出；文件名编码版本、配置和运行序号。 |
| `results/diffs/` | `*_log.txt`、`*_diffstat.txt` | 保存 Clang/GCC constant-time 修复、x86 汇编移除、固定基点乘法重构和默认 86 KiB 表等案例的固定提交日志与差异摘要。 |
| `report/` | `task2.tex`、`BUILD.md` | 中文 LaTeX 报告源文件，以及 XeLaTeX/`latexmk` 编译和 PDF 逐页检查命令。 |
| `output/pdf/` | `task2_secp256k1_report.pdf`、`task2_secp256k1_report.md` | 最终课程提交版任务二报告；Markdown 版保留同一正文、公式、代码、表格、流程图和参考文献。 |
| `work/secp256k1/` | 上游 Git 仓库镜像 | 用于获取固定 tag、commit 和差异证据，不是自行修改的项目源码。 |
| `work/sources/` | `v0.3.0` 至 `v0.7.1` 的固定版本源码 | 各研究版本的独立工作树，供源码核对和构建使用。 |
| `work/builds/` | `v0.3.0-default`、`v0.3.1-default`、`v0.3.2-default`，以及四个性能配置 | 七套本机 Release 构建目录；前三套验证安全修复前后版本，后四套用于性能 benchmark，其中动态库是 `library_sizes.csv` 的测量对象。 |
| `.venv/`、`work/`、`tmp/`、`__pycache__/` | 可重建的本地文件 | 虚拟环境、上游源码/构建树、LaTeX 构建缓存和 Python 字节码；体积较大且已被 `.gitignore` 忽略，不属于课程交付物。 |

最终提交时，重点保留 `scripts/`、`data/`、`results/`、`report/` 和 `output/pdf/`。删除 `work/` 后仍可通过完整复现命令重新下载、构建并生成报告使用的所有结构化数字。

## 复现实验

```bash
python3 -m venv .venv
.venv/bin/python -m pip install cmake ninja
.venv/bin/python scripts/reproduce.py --case all --runs 10 --warmups 2
.venv/bin/python scripts/forge_digest_demo.py
```

脚本会：

1. 从官方仓库获取 `v0.3.0`、`v0.3.1`、`v0.3.2`、`v0.4.0`、`v0.4.1`、`v0.5.0`、`v0.5.1` 和 `v0.7.1`。
2. 保存标签对应 commit、相关版本区间的 log/diff 和实验环境。
3. 使用同一 Clang Release 配置构建 `v0.3.0`、`v0.3.1`、`v0.3.2` 和四套性能配置，并运行全部七套官方测试。
4. 仅对 `v0.4.1` 默认配置与 `v0.5.0` 的 2/22/86 KiB 表执行预热和重复 benchmark，避免把安全版本构建混入性能对照组。
5. 自动测量动态库大小并输出 `library_sizes.csv`/JSON。
6. 输出原始日志、逐次 CSV 与 median/IQR/ops/s 汇总。
7. 运行 `forge_digest_demo.py` 后，另外生成不使用私钥的摘要伪造正反对照结果。

已有构建目录时，可不重跑测试和 benchmark，单独重新生成库大小结果：

```bash
.venv/bin/python scripts/reproduce.py --case sizes
```

`work/` 中的上游源码和 build tree 会被忽略；可提交产物只保留 `results/` 下的元数据、摘要和必要差异证据。

## 平台限制

本机是 Apple ARM64 + Apple Clang 17。`v0.4.1` 记录的 x86_64/GCC 性能提升以及 `v0.3.2` 的 GCC 13.1 ECDH constant-time 问题不能由本机 benchmark 直接复现，报告只引用上游证据并明确区分。

## 已验证结果

- `v0.3.0`、`v0.3.1`、`v0.3.2`、`v0.4.1` 与 `v0.5.0` 三种表配置均成功构建，七组官方 ctest 均为 3/3 通过。
- 每组 2 次预热、10 次正式运行：`ecdsa_sign` median 分别为 28.4、27.8、25.2、24.6 microseconds。
- 原始数据与汇总位于 `results/benchmark_runs.csv`、`results/benchmark_summary.csv` 和 `results/library_sizes.csv`。
- 报告：`output/pdf/task2_secp256k1_report.pdf`。
- 同内容 Markdown：`output/pdf/task2_secp256k1_report.md`。
