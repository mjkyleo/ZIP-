# ZIP 压缩包密码一键恢复工具（crack_zip.py v2）

> **本项目说明**：本项目**不是**独立实现的破解算法，而是对两个成熟开源项目的**整合封装**：
>
> - **[hashcat](https://hashcat.net/hashcat/)**（世界最快的密码恢复工具，GPU 加速）—— 用于对**小型加密条目**做 GPU 字典 / 规则 / 组合 / 掩码攻击，以及**多文件包的“仅校验和”快速预跑**（模式 17230）；
> - **[John the Ripper](https://www.openwall.com/john/)（Jumbo 版，含 zip2john）** —— 用于提取 ZIP 加密哈希，并对**大型加密条目**做 CPU 攻击（字典、规则、混合掩码、增量掩码、PRINCE、Markov、Incremental）。
>
> 本项目只负责把「提取哈希 → 判断格式与条目 → 选择引擎 → 攻击阶梯 → 校验密码 → 输出结果」串成一条自动化流水线，核心能力全部来自上述两个开源项目。官方社区与源码：
> - hashcat 论坛：<https://hashcat.net/forum/>
> - John the Ripper 源码：<https://github.com/openwall/john>
>
> **v2 说明**：本版依据两套官方文档（`hashcat-7.1.2\docs\` 与 `john-1.9.0-jumbo-1-win64\doc\`）通读后优化：补齐引擎选择（17220/17225/17230/13600 限制）、引入攻击阶梯（规则 / 混合掩码 / 增量掩码 / PRINCE / Markov / Incremental）、逐阶段实测速度与 keyspace 估算、17230 候选真实解密复验、会话隔离与 pot 直读。

---

## 1. 原理：什么是“从哈希破解压缩包密码”

压缩软件（WinZip / WinRAR / 7-Zip / Info-ZIP 等）加密 ZIP 时，**不会保存明文密码**，只保存密码参与运算后得到的**哈希摘要**（加密头、校验值等）。所谓“从哈希破解”，就是：

1. 用 `zip2john` 把压缩包里隐含的哈希**提取**出来（一个形如 `$pkzip2$...` 的字符串）；
2. 准备候选密码集（**字典**：常见密码列表；**掩码**：按规则枚举，如纯数字 2~8 位）；
3. 用 hashcat / john 对每个候选密码计算哈希，**和目标哈希比对**；
4. 匹配上即命中，最后用 Python `zipfile` **真实解密一次**做最终确认。

> ⚠️ **法律与安全提醒（务必阅读）**
> 本工具**仅允许**用于恢复**你本人拥有所有权、自己忘记密码**的压缩文件。
> 未经授权破解他人压缩包属于违法行为（侵犯隐私、著作权，可能触犯《治安管理处罚法》《刑法》），由此产生的法律责任由使用者自行承担。
> 破解完成后建议立即删除临时目录 `workSpace/temp` 中的哈希文件与字典等敏感中间文件。

---

## 2. 目录结构

```
E:\压缩包破解\
├─ crack_zip.py                      # 一键破解脚本（本项目的整合入口）
├─ README.md                         # 本文档
├─ hashcat-7.1.2\                    # 开源项目①：hashcat（GPU 破解引擎）
├─ john-1.9.0-jumbo-1-win64\         # 开源项目②：John the Ripper Jumbo（哈希提取 + CPU 破解）
│  └─ run\
│     ├─ zip2john.exe                # 提取 ZIP 哈希（支持 -c 仅校验和 / -o 单文件）
│     ├─ john.exe                    # CPU 破解引擎
│     └─ password.lst                # John 自带常用密码字典
└─ workSpace\
   ├─ raw\
   │  └─ target.zip                  # 待破解的压缩包（默认目标）
   ├─ temp\                          # 运行产生的临时文件（哈希、字典、pot、会话）
   └─ result\                        # 破解结果输出目录
      ├─ password.txt                # 破解出的密码（纯文本一行）
      └─ crack_report.log            # 破解报告（目标、格式、命中阶段、引擎、耗时）
```

---

## 3. 环境要求

| 组件 | 用途 | 说明 |
|---|---|---|
| Python 3.8+ | 运行主脚本 | 本机已验证 Python 3.14 / 3.11 |
| hashcat 7.x | GPU 破解引擎 | 需要 OpenCL 运行环境；NVIDIA 卡用驱动自带 OpenCL 即可（无需 CUDA Toolkit） |
| John the Ripper 1.9.0-jumbo-1 | 哈希提取 + CPU 破解 | 开箱即用，无需额外安装 |

> 关于 GPU：hashcat 同时支持 NVIDIA（CUDA/OpenCL）、AMD（OpenCL）、Intel（OpenCL）和纯 CPU。
> 本机（RTX 3050 Laptop）已验证：`hashcat -I` 可识别 `NVIDIA GeForce RTX 3050 Laptop GPU`。
> 若 hashcat 初始化 GPU 失败（如驱动缺失），脚本会自动回退到 John the Ripper 的 CPU 引擎，不影响使用。

---

## 4. 快速开始

```powershell
# 1) 把待破解的压缩包放到 workSpace\raw\ 下并命名为 target.zip（或任意名）

# 2) 一键破解（默认目标 workSpace\raw\target.zip，结果输出到 workSpace\result\）
python E:\压缩包破解\crack_zip.py

# 3) 查看结果
type E:\压缩包破解\workSpace\result\password.txt

# 4) 查看目标压缩包的哈希信息与引擎计划（不破解）
python E:\压缩包破解\crack_zip.py --info
```

脚本自动完成：
1. `zip2john` 提取加密哈希 → 2. 解析哈希头、判断加密格式 / 条目数 / 条目尺寸 → 3. 自动选择引擎与模式（见第 6 节）→ 4. 按**攻击阶梯**逐阶段攻击（见第 7 节）→ 5. 每个命中都用 `zipfile` 真实解密校验 → 6. 结果写入 `workSpace\result\`。

---

## 5. 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--target` | `workSpace/raw/target.zip` | 指定要破解的压缩包 |
| `--result-dir` | `workSpace/result` | 结果输出目录 |
| `--dict` | 无 | 附加自定义字典文件（每行一个候选密码） |
| `--masks` | `?d?d` 至 `?d?d?d?d?d?d?d?d` | 掩码列表（逗号分隔）。纯数字掩码会自动合并为**一次增量调用**（覆盖最短~最长） |
| `--ladder` | `standard` | 攻击阶梯：`minimal`=字典+规则；`standard`=+混合掩码+掩码；`full`=+PRINCE+Markov+Incremental |
| `--rules` | `All` | john 规则集（`john.conf` 的 `[List.Rules:xxx]`），默认 `All` |
| `--hashcat-rules` | `rules/best66.rule` | hashcat 规则文件（7.x 中 best64 已更名 best66） |
| `--time-limit` | 0（不限） | 总攻击时长上限（秒）。17230 预跑封顶 60 秒且不超过总时限的 30%，把剩余预算留给 john 主引擎 |
| `--skip-mask` | 关 | 跳过掩码攻击 |
| `--skip-rules` | 关 | 跳过规则攻击 |
| `--skip-hybrid` | 关 | 跳过混合掩码（词+数字后缀） |
| `--skip-prince` | 关 | 跳过 PRINCE 短语组合 |
| `--skip-markov` | 关 | 跳过 Markov 统计攻击 |
| `--skip-incremental` | 关 | 跳过 john Incremental（.chr） |
| `--no-checksum-pass` | 关 | 跳过 17230 校验和快速预跑 |
| `--python-only` | 关 | 不调用 hashcat/john，纯 Python 字典攻击（速度慢） |
| `--info` | 关 | 只解析哈希、打印条目信息与引擎计划后退出 |
| `--clean-temp` | 关 | 完成后删除临时目录（含哈希/字典/pot/会话） |

示例：

```powershell
# 破解指定压缩包 + 附加自己的字典
python crack_zip.py --target D:\mydata.zip --dict D:\my_dict.txt

# 完整攻击阶梯（PRINCE/Markov/Incremental）
python crack_zip.py --ladder full

# 总时长上限 10 分钟
python crack_zip.py --time-limit 600

# 只跑 6 位纯数字掩码
python crack_zip.py --masks "?d?d?d?d?d?d"

# 先字母后数字（如 abc123 型）
python crack_zip.py --masks "?l?l?l?d?d?d"

# 小写字母 5~6 位
python crack_zip.py --masks "?l?l?l?l?l,?l?l?l?l?l?l"
```

### 掩码语法速查

| 掩码符号 | 含义 |
|---|---|
| `?d` | 数字 0-9 |
| `?l` | 小写字母 a-z |
| `?u` | 大写字母 A-Z |
| `?a` | 大小写字母 + 数字 + 符号 |
| `?s` | 特殊符号 |
| `?b` | 全部 0x00-0xff |
| `?w` | john 混合掩码中代表“原字典词”（如 `?w?d?d` = 词+2 位数字） |

---

## 6. 引擎选择逻辑（文档驱动，重要）

脚本依据 `zip2john` 提取的哈希自动选择引擎与模式：

| 哈希格式 | 对应加密 | 条目情况 | 引擎 | hashcat 模式 |
|---|---|---|---|---|
| `$pkzip2$` | 传统 PKZIP（ZipCrypto） | 单条目压缩 ≤ 320 KB | **hashcat（GPU）** | `-m 17200`（压缩）/ `-m 17210`（存储） |
| `$pkzip2$` | 传统 PKZIP（ZipCrypto） | 多条目、全部 ≤ 320 KB | **hashcat（GPU）** | `-m 17220`（全压缩）/ `-m 17225`（混合） |
| `$pkzip2$` | 传统 PKZIP（ZipCrypto） | 多条目（≥2 个加密文件） | **hashcat 17230 校验和预跑 + john** | `-m 17230`（仅校验和，无数据、无尺寸限制） |
| `$pkzip2$` | 传统 PKZIP（ZipCrypto） | 单条目 > 320 KB | **John（CPU）** | 不适用 |
| `$zip2$` | WinZip AES（128/192/256） | 数据 ≤ 8 MB | hashcat（GPU，仅字典/规则） | `-m 13600` |
| `$zip2$` | WinZip AES | 数据 > 8 MB | John（CPU，`--format=zip`） | 不适用 |

**关键限制（来自 hashcat 内核源码与文档）**：
- hashcat `-m 17200/17210/17220/17225`（PKZIP）内核把整段密文放进固定结构体，**单条目压缩数据上限 320 KB**（`MAX_DATA`），超限报 `Token length exception`；校验需**解压整段数据**，无法截短哈希绕过；
- hashcat `-m 17230`（**Checksum-Only**）不需要完整密文：用 `zip2john -c` 生成“仅校验和”哈希（每个条目携带校验位 + 12 字节密文前缀），**不受 320 KB 限制**，多文件包可以走 GPU 快速预跑；命中的候选会逐个用真实解密复验，误报自动丢弃（实测 3 条目 × 8 位校验可 0 秒破解且无误报）；
- hashcat `-m 13600`（WinZip AES）**只有 a0（字典）内核**（`m13600-pure.cl`），不支持掩码/组合攻击——脚本会为 `$zip2$` 自动把掩码攻击转到 john；
- John the Ripper 的 `pkzip`/`zip` 格式**没有尺寸限制**（完整校验同样需要全量密文），因此大文件包自动走 john。

> 结论：**不是所有 ZIP 都能“一键秒破”**。密码熵、加密算法、条目大小共同决定可行性。本工具的目标是把**可破的**用最快的引擎破出来；破不动的会如实告知，绝不假装成功。

---

## 7. 攻击阶梯（attack ladder）

脚本按“便宜的先跑、命中即停”的顺序自动执行（每阶段命中后经真实解密验证即停止）：

| 顺序 | 阶段 | 引擎 | 说明 |
|---|---|---|---|
| 0 | pot 快恢复 | 双引擎 | 上次运行已破解则直接读 pot 输出 |
| 1 | 字典攻击 | hashcat / john | 内置常见密码表 + john `password.lst` + 用户字典 |
| 2 | 字典 + 规则 | hashcat `-r best66.rule` / john `--rules=All` | 追加数字、大小写、133t 等常见变形 |
| 3 | 混合掩码 | john `--mask='?w?d?d'` / `?w?d?d?d` | 字典词 + 数字后缀（如 `abc123` 型） |
| 4 | 增量掩码 | hashcat `-i` / john `--mask --min/max-length` | 纯数字 2~8 位合并为**一次**增量调用 |
| 5（full） | PRINCE | john | 字典词拼接成短语（`loveyou123` 型） |
| 6（full） | Markov | john | 基于统计的智能暴力（`.chr` 统计文件） |
| 7（full） | Incremental | john | `LowerNum`/`Digits` 等预置模式 |
| 8 | 逐条目回退 | john + `zip2john -o` | 多文件包各文件密码不同时逐个条目破解 |

> `standard` 为默认（1~4），`full` 增加 5~7。每阶段显示 keyspace 估算与参考速度（速度来自上一阶段实测 `p/s`，避免用基准测试误导——大数据条目的基准 c/s 与实测差百倍）。

---

## 8. 破不动怎么办？（进阶思路）

1. **换更大的字典**：常用密码库（SecLists、Have I Been Pwned 泄露密码集），用 `--dict` 传入；
2. **更精细的掩码**：结合密码特征。例如生日文档可试 `--masks "?d?d?d?d?d?d?d?d"`；
3. **规则集切换**：`--rules Single`（单模式）更小更快，`--rules All` 覆盖更广；hashcat 侧可换 `dive.rule`（`--hashcat-rules rules/dive.rule`）；
4. **延长时限**：`--time-limit 3600`；大字典 + `full` 阶梯 + 长时间是“尽力而为”的配置；
5. **哈希模式核实**：`$zip2$`（WinZip AES）≠ `$pkzip2$`（ZipCrypto），`-m 13600` 只适用于前者；脚本已自动区分；
6. **ZipCrypto 已知明文攻击（高级）**：传统 PKZIP（ZipCrypto）有结构性弱点，若知道包内文件任一段明文（如 PDF 的 `%PDF-` 头），可用 **bkcrack**（开源）直接恢复密钥与密码，与密码长度无关。本工具未集成，仅提示。

---

## 9. 常见问题（FAQ）

**Q1: 报 `hashcat: No such file or directory: ./OpenCL/`**
hashcat 依赖相对路径，必须在自己的目录下运行。脚本内部已处理（`cwd=hashcat 目录`）；手动操作时先 `cd E:\压缩包破解\hashcat-7.1.2`。

**Q2: 报 `Oversized line detected` / `Token length exception`**
条目 > 320 KB 超出 hashcat PKZIP 内核限制，脚本自动改用 john。手动：
```powershell
cd E:\压缩包破解\john-1.9.0-jumbo-1-win64\run
zip2john.exe "E:\压缩包破解\workSpace\raw\target.zip" > hash.txt
john.exe --format=pkzip --wordlist=password.lst --rules=All hash.txt
john.exe --format=pkzip --show hash.txt
```

**Q3: 报 `Failed to initialize NVIDIA RTC library` / `CUDA SDK Toolkit not installed`**
不影响 OpenCL 运行。hashcat 回退 OpenCL（本机已验证可用）。安装与显卡匹配的 CUDA Toolkit 可消除提示。

**Q4: 多文件 zip 的 17230 预跑提示“误报”然后继续**
正常。校验和模式只有有限校验位，大 keyspace 攻击可能产生少量匹配 24~48 位的“假阳性”候选；脚本逐个用真实解密复验，自动丢弃假阳性并继续，直到找到真密码或跑完所有阶段。

**Q5: 破解很慢 / 进度不明显**
- `hashcat -I` 确认 GPU 被识别；
- john 引擎多线程 CPU（本机 12 线程实测约 76 万次/秒（小条目），大条目因需全量解压会更慢）；
- 大 keyspace 阶段会显示 keyspace 与参考速度估算，可据此判断是否值得等待。

**Q6: 为什么有的包几秒就破，有的永远破不动？**
取决于密码熵与算法。纯数字 6 位（100 万组合）GPU 秒级；8 位混合密码即使多卡集群也要以年计。密码强度是安全的核心：建议 12 位以上混合密码 + 密码管理器。

**Q7: 中断后重新运行会从头再来吗？**
不会。john/hashcat 的 pot 文件（`workSpace\temp\*.pot`）记录了已破解结果，重新运行会先读 pot 直接输出；尚未破解的部分会重新攻击。

---

## 10. 性能参考（本机实测）

| 硬件 / 引擎 | 实测速率 | 纯数字 6 位 | 纯数字 8 位 |
|---|---|---|---|
| John（12 线程 CPU，PKZIP 小条目） | ~76 万次/秒 | ~1.3 秒 | ~2.2 分钟 |
| John（12 线程 CPU，PKZIP 90MB 大条目） | ~42 万次/秒（字典）/ 753 万次/秒（规则） | — | — |
| hashcat（RTX 3050，17230 校验和） | ~4 百万~1 亿次/秒（随 keyspace 提升） | 秒级 | ~10 秒 |
| 4×RTX 4090 集群（RAR5 参考） | ~52 万次/秒 | 秒级 | ~3 分钟 |

> 以上为 PKZIP（ZipCrypto）这类“轻校验”格式。RAR5、WinZip AES 哈希计算成本高得多，速度低 1~2 个数量级。

---

## 11. 数据安全与清理

破解过程中会在 `workSpace\temp\` 产生：
- `target.hash`（提取的哈希，**大文件可达数百 MB**，因其内含完整密文）；
- `target_check.hash`（17230 校验和哈希，很小）；
- `dict_combined.txt`（合并字典）；
- `john.pot` / `hashcat.pot`（已破解记录，**内含明文密码**）；
- `cz_*.rec`（john 会话，阶段结束后自动清理）。

**建议破解完成后删除整个 `workSpace\temp\` 目录**（或运行 `python crack_zip.py --clean-temp`），避免哈希、密码、字典等敏感信息长期留存。重跑时脚本会自动重建。

---

## 12. 致谢与参考

- [hashcat](https://hashcat.net/hashcat/) · [hashcat 官方论坛](https://hashcat.net/forum/) · [hashcat 示例哈希与模式表](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [John the Ripper](https://www.openwall.com/john/) · [John the Ripper GitHub（Jumbo）](https://github.com/openwall/john)
- 本机随包文档：`hashcat-7.1.2\docs\`（readme.txt / hashcat-help.md / limits.txt / rules.txt / hashcat-example-hashes.md）、`john-1.9.0-jumbo-1-win64\doc\`（OPTIONS.txt / RULES.txt / MASK.txt / MODES.txt / PRINCE.txt / MARKOV.txt / EXAMPLES.txt / FAQ.txt / README-ZIP.txt）
- 参考教程：<https://blog.junmoyu.com/posts/hashcat-cracked-zip/>

本项目仅做流程封装与自动化，无任何原创破解算法；一切能力归功于 hashcat 与 John the Ripper 开源社区。
