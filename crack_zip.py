# -*- coding: utf-8 -*-
"""
crack_zip.py v2 — ZIP 压缩包密码一键恢复工具
（基于 hashcat 与 John the Ripper 两个开源项目的流程整合封装，非原创算法）

原理
----
压缩软件加密 ZIP 时不会保存明文密码，只保存密码参与运算后得到的“哈希摘要”。
本工具先用 John the Ripper 的 zip2john 把压缩包的加密哈希提取出来，再交给
hashcat（GPU 加速）或 John the Ripper（CPU）对候选密码做多种攻击，命中后用
Python zipfile 真实解密一次做最终确认，并把密码写入结果目录。

本版优化（依据 hashcat 7.1.2 docs/ 与 john 1.9.0-jumbo-1 doc/ 官方文档）：
1. 更准确的引擎选择：
   * $pkzip2$ 传统 ZipCrypto：hashcat 17200（压缩）/17210（存储）/17220/17225（多文件）
     受 320KB/条目 内核限制；超限自动走 john --format=pkzip（无尺寸限制）
   * 多文件包（>=3 个加密条目、足够校验位）额外生成“仅校验和”哈希（zip2john -c），
     用 hashcat 17230 做无数据快速预跑（不受 320KB 限制）
   * $zip2$ WinZip AES：hashcat 13600 仅支持字典攻击内核（m13600-pure.cl 只有 a0），
     掩码攻击自动转 john --format=zip
2. 攻击阶梯（attack ladder）：字典 -> 字典+规则 -> 混合掩码（词+数字）-> 增量掩码
   -> PRINCE 短语组合 -> Markov 统计 -> Incremental（.chr）-> 多文件逐条目回退
3. 进度与估算：掩码 keyspace 数学估算 + john 基准速度 + 阶段耗时显示
4. 健壮性：hashcat/john 分离 pot、阶段会话名、超时限制（--time-limit）、
   pot 快恢复（上次已破解则直接输出）、17230 命中必须真实解密验证（防误报）

用法
----
    python crack_zip.py                          # 默认目标 workSpace/raw/target.zip
    python crack_zip.py --target xxx.zip
    python crack_zip.py --dict my.txt            # 附加自定义字典
    python crack_zip.py --masks '?l?l?l?l?l'     # 自定义固定长度掩码
    python crack_zip.py --ladder full            # 完整攻击阶梯（含 PRINCE/Markov/Incremental）
    python crack_zip.py --time-limit 600         # 总时长上限（秒）
    python crack_zip.py --info                   # 只解析哈希并打印引擎计划，不破解

仅限用于恢复你本人拥有所有权、自己忘记密码的压缩文件。
"""

import argparse
import io
import itertools
import os
import re
import subprocess
import sys
import time
import zipfile

# ----------------------------------------------------------------------------
# 路径配置
# ----------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TARGET = os.path.join(ROOT, "workSpace", "raw", "target.zip")
DEFAULT_RESULT_DIR = os.path.join(ROOT, "workSpace", "result")
TEMP_DIR = os.path.join(ROOT, "workSpace", "temp")

HASHCAT_DIR = os.path.join(ROOT, "hashcat-7.1.2")
HASHCAT_EXE = os.path.join(HASHCAT_DIR, "hashcat.exe")
JOHN_RUN_DIR = os.path.join(ROOT, "john-1.9.0-jumbo-1-win64", "run")
ZIP2JOHN_EXE = os.path.join(JOHN_RUN_DIR, "zip2john.exe")
JOHN_EXE = os.path.join(JOHN_RUN_DIR, "john.exe")
JOHN_PASSWORD_LST = os.path.join(JOHN_RUN_DIR, "password.lst")

# hashcat 17200/17210/17220/17225 内核硬限制：单条目压缩数据不超过 320KB
HASHCAT_MAX_DATA = 320 * 1024
# hashcat 13600（WinZip AES）内核数据上限（8MB）
HASHCAT_MAX_DATA_AES = 8 * 1024 * 1024
# hashcat 规则文件（7.x 中 best64 已更名 best66）
HASHCAT_RULES = os.path.join("rules", "best66.rule")

# john 规则集（john.conf [List.Rules:xxx]）
JOHN_RULESET_DEFAULT = "All"

# 17230 仅校验和模式的触发门槛：多条目包（>=2 个加密条目即可，每个条目贡献
# 16 位校验 + 12 字节密文前缀，实测 cnt=3 时无误报；任何命中都会用真实解密复验）
def _checksum_pass_ok(meta):
    return meta["format"] == "pkzip2" and meta.get("parse_ok") and meta["cnt"] >= 2


# 内置常用密码表（常见中文 / 英文弱密码，覆盖大量真实场景）
BUILTIN_DICT = """123456
123456789
12345678
1234567
1234567890
password
qwerty
qwerty123
abc123
111111
123123
123321
666666
888888
520520
521521
woaini
woaini1314
iloveyou
admin
administrator
root
toor
test
guest
letmein
welcome
monkey
dragon
master
shadow
sunshine
princess
football
baseball
superman
batman
pokemon
michael
jennifer
daniel
123abc
abcabc
aa123456
a123456
a123456789
wang123
zhang123
li123456
chen123
liu123
zhao123
huang123
sun123
zhou123
wu123
xu123
zheng123
ma123
zhu123
hu123
guo123
he123
lin123
luo123
gao123
liang123
song123
tang123
han123
feng123
deng123
cao123
peng123
zeng123
xiao123
tian123
dong123
pan123
yuan123
du123
ye123
jiang123
cheng123
shen123
yu123
zhong123
lv123
wang1234
zhang1234
li1234
chen1234
liu1234
zhao1234
huang1234
wang888
zhang888
wang666
zhang666
woshishui
nihao
nihao123
xiexie
caonima
tmd123
fuck
fuckyou
sex
sexy
love
lover
lovely
baby
baby123
honey
sweet
girl
boy
handsome
beauty
pretty
flower
dream
happy
happy123
sunny
rainbow
star
stars
moon
sky
sky123
cloud
world
world123
hello
hello123
hello1234
hi123
ok123
ok123456
zxcvbnm
asdfgh
asdfghjkl
qazwsx
qazwsxedc
1qaz2wsx
1q2w3e4r
1q2w3e
zaq12wsx
qwer1234
asdf1234
zxcv1234
poiuyt
987654321
87654321
7654321
654321
54321
4321
321
112233
11223344
123654
456789
102030
100200
102938
135790
159357
147258
258369
369258
741852
852963
963852
98765
123456789a
123456789b
abc123456
abcd1234
abcd123
abcdef
abcdefg
abcdefgh
1a2b3c4d
a1b2c3d4
a1b2c3
zxc123
asd123
asd456
qwe123
qwe456
qweasd
zxcvasd
password1
password123
passw0rd
p@ssw0rd
p@ssword
P@ssw0rd
P@ssword123
Passw0rd!
password!
Password1
Secret
secret
secret123
secret888
myself
mypass
mypassword
mysecret
mima
mima123
yhm123
mm123456
wodemima
wodemima123
aini
aini1314
woainima
woaini520
5201314
1314520
1314521
5201314520
1314520520
1314
520
7758521
7758520
7758258
741741
147147
258258
369369
000000
0000000
00000000
11111111
222222
333333
444444
555555
777777
999999
10086
10010
10000
95588
95533
95599
95566
95169
110110
120120
119119
114114
168168
518518
886886
998998
996996
123000
123456000
1988
1989
1990
1991
1992
1993
1994
1995
1996
1997
1998
1999
2000
2001
2002
2003
2004
2005
2006
2007
2008
2009
2010
2011
2012
2013
2014
2015
2016
2017
2018
2019
2020
2021
2022
2023
2024
2025
2026
19880101
19890101
19900101
19910101
19920101
19930101
19940101
19950101
19960101
19970101
19980101
19990101
20000101
20010101
20020101
20030101
20040101
20050101
20060101
20070101
20080101
20090101
20100101
20110101
20120101
20130101
20140101
20150101
20160101
20170101
20180101
20190101
20200101
20210101
20220101
20230101
20240101
20250101
woaini5201314
5201314woaini
1314520woaini
wodemima123
woaini888
wj1314
wy1314
lj1314
xy1314
"""

# 常见中文短句密码（按 UTF-8 写入）
BUILTIN_DICT_CN = """密码
密码123
我爱你
我爱你1314
老婆
老公
宝贝
亲爱的
生日快乐
生日快乐888
加油
努力
奋斗
成功
发财
平安
健康
幸福
快乐
吉祥
如意
一帆风顺
万事如意
心想事成
天天开心
好运
招财进宝
"""


# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%.1fTB" % n


def fmt_dur(sec):
    if sec < 60:
        return "%.1f 秒" % sec
    if sec < 3600:
        return "%d 分 %d 秒" % (int(sec // 60), int(sec % 60))
    return "%d 小时 %d 分" % (int(sec // 3600), int(sec % 3600 // 60))


def run_cmd(cmd, cwd=None, timeout=None, stream=None, on_line=None):
    """执行外部命令。
    stream=True 时逐行读取（配合 on_line 回调转发进度），返回 (returncode, 全文)。
    """
    env = os.environ.copy()
    try:
        if stream:
            # 注意：二进制流不能用 bufsize=1，逐行迭代由默认缓冲完成
            p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, env=env)
        else:
            p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, env=env)
    except OSError as e:
        return -1, "启动失败: %s" % e
    chunks = []
    if stream:
        for raw in p.stdout:
            chunks.append(raw)
            if on_line:
                on_line(raw)
        p.wait()
    else:
        try:
            out, _ = p.communicate(timeout=timeout)
            chunks.append(out)
        except subprocess.TimeoutExpired:
            p.kill()
            out, _ = p.communicate()
            chunks.append((out or b"") + b"\n[timeout expired]")
        p.wait()
    text = b"".join(chunks).decode("utf-8", errors="replace")
    return p.returncode, text


def read_file(path, encoding="utf-8", errors="replace"):
    with io.open(path, "r", encoding=encoding, errors=errors) as f:
        return f.read()


def write_file(path, content, encoding="utf-8"):
    with io.open(path, "w", encoding=encoding) as f:
        f.write(content)


# ----------------------------------------------------------------------------
# 1. 用 zip2john 提取压缩包哈希
# ----------------------------------------------------------------------------
def extract_zip_hash(zip_path, checksum_only=False):
    """运行 zip2john。
    checksum_only=True 时加 -c（仅校验和哈希，供 hashcat 17230 使用）。
    返回 (format, full_hash_line, meta)。
    """
    if not os.path.isfile(zip_path):
        raise FileNotFoundError("找不到目标压缩包: %s" % zip_path)
    tag = "校验和哈希" if checksum_only else "加密哈希"
    log("步骤1: 用 zip2john 提取%s ..." % tag)
    cmd = [ZIP2JOHN_EXE]
    if checksum_only:
        cmd.append("-c")
    cmd.append(zip_path)
    rc, out = run_cmd(cmd, timeout=600)
    if "$pkzip2$" not in out and "$zip2$" not in out and "$pkzip$" not in out:
        raise RuntimeError(
            "zip2john 未提取到加密哈希。可能原因：压缩包未加密，或加密方式不受支持。\n"
            "zip2john 输出片段:\n" + out[:300])

    start = out.find("$pkzip2$")
    fmt = "pkzip2"
    if start == -1:
        start = out.find("$zip2$")
        fmt = "zip2"
    if start == -1:
        start = out.find("$pkzip$")
        fmt = "pkzip1"
    end_marker = {"pkzip2": "*$/pkzip2$", "zip2": "*$/zip2$", "pkzip1": "*$/pkzip$"}[fmt]
    end = out.find(end_marker, start)
    if end == -1:
        raise RuntimeError("zip2john 输出格式异常，未找到哈希结束标记。")
    full_hash = out[start:end + len(end_marker)]

    meta = {"format": fmt, "hash_len": len(full_hash), "checksum_only": checksum_only}
    if fmt in ("pkzip2", "pkzip1"):
        meta.update(parse_pkzip2(full_hash))
    elif fmt == "zip2":
        meta.update(parse_zip2(full_hash))
    log("提取成功: 格式=%s 哈希长度=%s%s" % (
        meta["format"], fmt_bytes(len(full_hash)),
        "（仅校验和）" if checksum_only else ""))
    return fmt, full_hash, meta


def parse_pkzip2(hash_line):
    """解析 $pkzip2$ 哈希头字段（字段定义参考 john 的 pkzip_fmt_plug.c）。
    解析失败时返回仅含 format 的 meta（后续仍以原始哈希文件为准）。"""
    base = {"cnt": 0, "chk_bytes": 1, "entries": [], "parse_ok": False}
    body = hash_line
    marker = "*$/pkzip2$"
    if marker in body:
        body = body[:body.rfind(marker)]
    toks = body.split("*")
    if len(toks) < 3:
        return base
    sig = toks[0]
    try:
        cnt = int(sig.replace("$pkzip2$", "").replace("$pkzip$", ""))
        chk_bytes = int(toks[1])
    except ValueError:
        return base
    base["cnt"] = cnt
    base["chk_bytes"] = chk_bytes
    idx = 2
    entries = []
    try:
        for _ in range(cnt):
            e = {"type": 2, "comptype": 8, "complen": 0, "declen": 0}
            e["type"] = int(toks[idx]); idx += 1
            e["magic"] = toks[idx]; idx += 1
            if e["type"] > 1:
                e["complen"] = int(toks[idx], 16); idx += 1
                e["declen"] = int(toks[idx], 16); idx += 1
                e["crc32"] = toks[idx]; idx += 1
                e["offset"] = toks[idx]; idx += 1
                e["offex"] = toks[idx]; idx += 1
            e["comptype"] = int(toks[idx]); idx += 1
            e["datalen"] = int(toks[idx], 16); idx += 1
            e["chk1"] = toks[idx]; idx += 1
            # 注意：pkzip2 格式条目固定携带两个 4-hex 校验字段
            if e["type"] > 1:
                e["chk2"] = toks[idx]; idx += 1
            else:
                e["chk2"] = toks[idx] if idx < len(toks) - 1 and len(toks[idx]) == 4 else None
                if e["chk2"] is not None:
                    idx += 1
            e["data_hexlen"] = len(toks[idx]) if idx < len(toks) else 0
            idx += 1
            entries.append(e)
    except (ValueError, IndexError):
        base["parse_ok"] = False
        base["entries"] = []
        return base
    base["entries"] = entries
    base["parse_ok"] = True
    return base


def parse_zip2(hash_line):
    """解析 $zip2$ 哈希头字段"""
    body = hash_line[:hash_line.rfind("*$/zip2$")]
    toks = body.split("*")
    try:
        return {"type": toks[1], "mode": toks[2], "complen": int(toks[6]), "parse_ok": True}
    except (ValueError, IndexError):
        return {"type": "", "mode": "", "complen": 0, "parse_ok": False}


# ----------------------------------------------------------------------------
# 2. 引擎选择
# ----------------------------------------------------------------------------
def choose_engine(meta):
    """返回引擎计划 dict：
    {
      'hashcat_modes': [..],      # 可按顺序尝试的 hashcat 模式（小哈希）
      'checksum_ok': bool,        # 是否可做 17230 校验和快速预跑
      'john_format': str|None,    # john 格式名（主引擎）
    }
    """
    plan = {"hashcat_modes": [], "checksum_ok": False, "john_format": None}
    if meta["format"] == "zip2":
        # 13600 只有 a0 字典内核（见 m13600-pure.cl），数据上限 8MB
        if meta.get("parse_ok") and meta.get("complen", 0) <= HASHCAT_MAX_DATA_AES:
            plan["hashcat_modes"] = [13600]
        plan["john_format"] = "zip"
        return plan
    if meta["format"] in ("pkzip2", "pkzip1"):
        plan["john_format"] = "pkzip"
        if meta.get("parse_ok") and meta["cnt"] > 0:
            entries = meta["entries"]
            # 校验和快速预跑：多条目包（17230 无数据、无 320KB 限制）
            if not meta.get("checksum_only") and _checksum_pass_ok(meta):
                plan["checksum_ok"] = True
            # 常规 hashcat 模式：所有条目压缩数据 <= 320KB 才可用
            if all(e["type"] > 1 and e["complen"] <= HASHCAT_MAX_DATA for e in entries):
                if meta["cnt"] == 1:
                    e = entries[0]
                    plan["hashcat_modes"] = [17210 if e["comptype"] == 0 else 17200]
                else:
                    if all(e["comptype"] == 8 for e in entries):
                        plan["hashcat_modes"] = [17220]
                    else:
                        plan["hashcat_modes"] = [17225]
        return plan
    # 未知格式兜底
    plan["john_format"] = "pkzip"
    return plan


# ----------------------------------------------------------------------------
# 3. 字典
# ----------------------------------------------------------------------------
def make_dict(extra_dict=None):
    """生成合并字典文件（内置 + john password.lst + 用户字典），返回 (路径, 条数)"""
    dict_path = os.path.join(TEMP_DIR, "dict_combined.txt")
    ensure_dir(TEMP_DIR)
    lines = set()
    for item in BUILTIN_DICT.splitlines() + BUILTIN_DICT_CN.splitlines():
        item = item.strip()
        if item:
            lines.add(item)
    if os.path.isfile(JOHN_PASSWORD_LST):
        for ln in read_file(JOHN_PASSWORD_LST).splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                lines.add(ln)
    if extra_dict and os.path.isfile(extra_dict):
        for ln in read_file(extra_dict).splitlines():
            ln = ln.strip()
            if ln:
                lines.add(ln)
    write_file(dict_path, "\n".join(sorted(lines, key=lambda x: (len(x), x))) + "\n")
    return dict_path, len(lines)


def dict_has_non_ascii(dict_path):
    """字典是否含非 ASCII（用于给 john 加 --encoding=utf-8）"""
    with io.open(dict_path, "rb") as f:
        head = f.read(65536)
    return any(b > 127 for b in head)


# ----------------------------------------------------------------------------
# 4. 攻击执行（hashcat）
# ----------------------------------------------------------------------------
def decode_hashcat_plain(pw):
    if pw.startswith("$HEX[") and pw.endswith("]"):
        try:
            return bytes.fromhex(pw[5:-1]).decode("utf-8", errors="replace")
        except ValueError:
            return pw
    return pw


def parse_hashcat_pot_file(pot_path):
    """直接解析 hashcat pot 文件，返回全部候选明文。
    注意：不能依赖 hashcat --show——同一哈希的多个候选（--keep-guessing 场景）
    在 --show 里只会显示最后一个。pot 行格式: <hash>:<plain>。"""
    if not (os.path.isfile(pot_path) and os.path.getsize(pot_path) > 0):
        return []
    res = []
    try:
        with io.open(pot_path, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line or ":" not in line:
                    continue
                pw = decode_hashcat_plain(line.split(":", 1)[1])
                if pw and pw not in res:
                    res.append(pw)
    except OSError:
        return []
    return res


def read_hashcat_pot_all(mode, hash_path, pot_path):
    """从 hashcat pot 读取全部已破解密码（直接解析 pot 文件）"""
    return parse_hashcat_pot_file(pot_path)


def read_hashcat_pot(mode, hash_path, pot_path):
    """从 hashcat pot 读取已破解密码（取第一个）"""
    res = read_hashcat_pot_all(mode, hash_path, pot_path)
    return res[0] if res else None


def run_hashcat(mode, hash_path, pot_path, attack_args, desc,
                time_limit=None, stream=True, session_tag="stage"):
    """运行一次 hashcat 攻击，返回 (rc, out)。
    session_tag 用于生成唯一会话名，避免共享会话导致的 restore 干扰。"""
    session = "hc_%d_%s_%d" % (mode, session_tag, os.getpid())
    cmd = [HASHCAT_EXE, "-m", str(mode), hash_path] + attack_args + [
        "--potfile-path", pot_path, "-w", "3", "--force",
        "--status", "--status-timer", "30", "--session", session]
    if time_limit:
        cmd += ["--runtime", str(time_limit)]
    log("  [hashcat] %s" % desc)
    log("  命令: %s ..." % " ".join(cmd[:8]))

    def on_line(raw):
        line = raw.decode("utf-8", errors="replace").strip()
        for kw in ("Speed.#1", "Progress", "Session.", "Candidates.#1",
                   "Cracked", "Recovered", "ERROR", "Token length",
                   "Oversized", "No devices"):
            if kw in line:
                log("    " + line[:160])
                break

    rc, out = run_cmd(cmd, cwd=HASHCAT_DIR, stream=stream, on_line=on_line)
    return rc, out


def crack_hashcat(hash_path, mode, dict_path, masks, pot_path, time_limit,
                  with_rules=True, keep_guessing=False, verifier=None):
    """hashcat 攻击阶梯（a0 字典 -> a0+规则 -> a1 组合 -> a3 掩码）。
    17200/17210/17220/17225/17230 支持 a0/a1/a3 内核；13600 仅 a0。
    keep_guessing=True（校验和模式）时全部命中都收集并返回列表。
    verifier=callable(pw)->bool：每阶段后立即验证候选，命中即提前停止。
    返回候选密码列表（空=未命中）。"""
    log("步骤: hashcat -m %d（GPU 加速%s）" % (
        mode, "，keep-guessing 收集全部候选" if keep_guessing else ""))
    t0 = time.time()
    modes_with_mask = mode not in (13600,)  # 13600 无掩码内核
    found = []

    def pot_now():
        cands = read_hashcat_pot_all(mode, hash_path, pot_path)
        if verifier and cands:
            for pw in cands:
                if verifier(pw):
                    return [pw]
        return cands

    # 4.1 字典攻击
    if dict_path:
        found = pot_now()
        if found and not keep_guessing:
            return found
        extra = ["--keep-guessing"] if keep_guessing else []
        rc, out = run_hashcat(mode, hash_path, pot_path,
                              ["-a", "0", dict_path] + extra,
                              "字典攻击（%d 条）" % _dict_count(dict_path), time_limit,
                              session_tag="dict")
        found = pot_now()
        if found and not keep_guessing:
            return found
        # 4.2 字典 + 规则
        if with_rules and os.path.isfile(os.path.join(HASHCAT_DIR, HASHCAT_RULES)):
            if time_limit and time.time() - t0 > time_limit:
                return found
            rc, out = run_hashcat(
                mode, hash_path, pot_path,
                ["-a", "0", dict_path, "-r", HASHCAT_RULES] + extra,
                "字典+规则（%s）" % os.path.basename(HASHCAT_RULES), time_limit,
                session_tag="rules")
            found = pot_now()
            if found and not keep_guessing:
                return found
        # 4.3 组合攻击（字典 x 字典，仅当字典较小时）
        if modes_with_mask and _dict_count(dict_path) <= 5000:
            rc, out = run_hashcat(mode, hash_path, pot_path,
                                  ["-a", "1", dict_path, dict_path] + extra,
                                  "组合攻击（字典 x 字典）", time_limit,
                                  session_tag="comb")
            found = pot_now()
            if found and not keep_guessing:
                return found
    # 4.4 掩码攻击：纯数字掩码合并为一次 -i 增量（min~max 长度）
    if modes_with_mask and masks:
        digit_masks = [m for m in masks if is_digit_mask(m)]
        other_masks = [m for m in masks if not is_digit_mask(m)]
        if digit_masks:
            if time_limit and time.time() - t0 > time_limit:
                log("  已达时间上限，跳过掩码")
                return found
            # 注意：len("?d?d") 是字符数 4，数字位数 = len//2
            lengths = sorted({len(m) // 2 for m in digit_masks})
            lo, hi = lengths[0], lengths[-1]
            mask = "?d" * hi
            rc, out = run_hashcat(mode, hash_path, pot_path,
                                  ["-a", "3", "-i",
                                   "--increment-min", str(lo),
                                   "--increment-max", str(hi), mask] + extra,
                                  "掩码 ?d%d~%d 位（增量，keyspace≈%.3g）" % (
                                      lo, hi, sum(10 ** n for n in range(lo, hi + 1))),
                                  time_limit, session_tag="maskd")
            found = pot_now()
            if found and not keep_guessing:
                return found
        for m in other_masks:
            if time_limit and time.time() - t0 > time_limit:
                log("  已达时间上限，跳过剩余掩码")
                return found
            ks = estimate_mask_size(m)
            rc, out = run_hashcat(mode, hash_path, pot_path,
                                  ["-a", "3", m] + extra,
                                  "掩码 %s（keyspace≈%.3g）" % (m, ks), time_limit,
                                  session_tag="mask")
            found = pot_now()
            if found and not keep_guessing:
                return found
    if not found:
        log("  hashcat 该轮未命中")
    return found


def _dict_count(dict_path):
    try:
        return sum(1 for _ in io.open(dict_path, "r", encoding="utf-8", errors="replace"))
    except OSError:
        return 0


# ----------------------------------------------------------------------------
# 5. 攻击执行（john）
# ----------------------------------------------------------------------------
def run_john(hash_path, pot_path, attack_args, desc, time_limit=None,
             session_suffix="", format_name="pkzip", encoding_utf8=False,
             speed_ref=None):
    """运行一次 john 攻击，返回 (rc, out)。
    speed_ref: dict，用于回填该阶段实测速度（p/s）"""
    session = "cz_%s_%d" % (session_suffix, os.getpid())
    cmd = [JOHN_EXE, "--format=" + format_name, "--pot=" + pot_path,
           "--session=" + session, "--no-log"]
    if encoding_utf8:
        cmd.append("--encoding=utf-8")
    cmd += attack_args + [hash_path]
    if time_limit:
        cmd += ["--max-run-time", str(int(time_limit))]
    log("  [john] %s" % desc)
    log("  命令: %s ..." % " ".join(cmd[:6]))

    def on_line(raw):
        line = raw.decode("utf-8", errors="replace").strip()
        if speed_ref is not None:
            capture_speed(line, speed_ref)
        for kw in ("g/s", "p/s", "Cracked", "cracked", "Session completed",
                   "No password hashes", "ERROR", "keyspace"):
            if kw in line:
                log("    " + line[:160])
                break

    rc, out = run_cmd(cmd, stream=True, on_line=on_line)
    # 清理会话文件（.rec 落在 john run 目录，逐阶段删除避免累积）
    try:
        for fn in os.listdir(JOHN_RUN_DIR):
            if fn.startswith("cz_") and fn.endswith(".rec"):
                os.remove(os.path.join(JOHN_RUN_DIR, fn))
    except OSError:
        pass
    return rc, out


def read_john_pot(hash_path, pot_path, format_name="pkzip"):
    """从 john pot 读取已破解密码"""
    if not (os.path.isfile(pot_path) and os.path.getsize(pot_path) > 0):
        return None
    rc, out = run_cmd([JOHN_EXE, "--format=" + format_name, "--show",
                       "--pot=" + pot_path, hash_path], timeout=120)
    for line in out.splitlines():
        if ":" in line and " left" not in line:
            pw = line.split(":", 1)[1].strip()
            if pw and not pw.startswith("0 ") and "password hash" not in pw:
                return pw
    return None


def bench_john_speed(format_name="pkzip"):
    """（已弃用）john --test 的 c/s 对大数据条目不具代表性，速度改为从各阶段实测捕获。
    本函数仅保留用于小哈希场景参考。"""
    return 0.0


def crack_john(hash_path, dict_path, masks, pot_path, ruleset, time_limit,
               ladder="standard", format_name="pkzip", skip_flags=None,
               hybrid_suffixes=("?w?d?d", "?w?d?d?d")):
    """john 攻击阶梯：字典 -> 字典+规则 -> 混合掩码 -> 增量掩码 -> PRINCE/Markov/Incremental。
    返回 (password, hit_stage)。"""
    skip_flags = skip_flags or {}
    t0 = time.time()
    speed_ref = {}
    enc = dict_has_non_ascii(dict_path) if dict_path else False

    def left():
        if time_limit:
            return max(0, int(time_limit - (time.time() - t0)))
        return None

    # 5.1 字典
    if dict_path and not skip_flags.get("dict"):
        pw = read_john_pot(hash_path, pot_path, format_name)
        if pw:
            return pw, "pot(上次结果)"
        rc, out = run_john(hash_path, pot_path, ["--wordlist=" + dict_path],
                           "字典攻击（%d 条）" % _dict_count(dict_path),
                           left(), "dict", format_name, enc, speed_ref)
        pw = read_john_pot(hash_path, pot_path, format_name)
        if pw:
            return pw, "字典"
    # 5.2 字典 + 规则
    if dict_path and ruleset and not skip_flags.get("rules"):
        pw = read_john_pot(hash_path, pot_path, format_name)
        if pw:
            return pw, "pot(上次结果)"
        rc, out = run_john(hash_path, pot_path,
                           ["--wordlist=" + dict_path, "--rules=" + ruleset],
                           "字典+规则（%s）" % ruleset,
                           left(), "rules", format_name, enc, speed_ref)
        pw = read_john_pot(hash_path, pot_path, format_name)
        if pw:
            return pw, "字典+规则(%s)" % ruleset
    # 5.3 混合掩码：词 + 数字后缀
    if dict_path and not skip_flags.get("hybrid"):
        for suf in hybrid_suffixes:
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "pot(上次结果)"
            ks = estimate_mask_size(suf) * _dict_count(dict_path)
            rc, out = run_john(hash_path, pot_path,
                               ["--wordlist=" + dict_path, "--mask=" + suf],
                               "混合掩码 %s（%s）" % (suf, eta_line(ks, speed_ref)),
                               left(), "hybrid_" + suf.replace("?", ""),
                               format_name, enc, speed_ref)
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "混合掩码(%s)" % suf
    # 5.4 掩码：纯数字掩码合并为一次 john 增量掩码（min~max 长度一次跑完）
    if masks and not skip_flags.get("mask"):
        digit_masks = [m for m in masks if is_digit_mask(m)]
        other_masks = [m for m in masks if not is_digit_mask(m)]
        if digit_masks:
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "pot(上次结果)"
            lengths = sorted({len(m) // 2 for m in digit_masks})
            lo, hi = lengths[0], lengths[-1]
            ks = sum(10 ** n for n in range(lo, hi + 1))
            rc, out = run_john(hash_path, pot_path,
                               ["--mask=?d", "--min-length=" + str(lo),
                                "--max-length=" + str(hi)],
                               "掩码 ?d%d~%d 位（%s）" % (lo, hi, eta_line(ks, speed_ref)),
                               left(), "mask_d%d_%d" % (lo, hi), format_name, enc,
                               speed_ref)
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "掩码(?d%d~%d)" % (lo, hi)
        for m in other_masks:
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "pot(上次结果)"
            ks = estimate_mask_size(m)
            rc, out = run_john(hash_path, pot_path, ["--mask=" + m],
                               "掩码 %s（%s）" % (m, eta_line(ks, speed_ref)),
                               left(), "mask_" + m.replace("?", ""), format_name,
                               enc, speed_ref)
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "掩码(%s)" % m
    # ---- full 阶梯：PRINCE / Markov / Incremental ----
    if ladder == "full":
        if dict_path and not skip_flags.get("prince"):
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "pot(上次结果)"
            rc, out = run_john(hash_path, pot_path,
                               ["--prince=" + dict_path, "--max-length=8",
                                "--min-length=4"],
                               "PRINCE 短语组合（字典词拼接，≤8 位）",
                               left(), "prince", format_name, enc, speed_ref)
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "PRINCE"
        if not skip_flags.get("markov"):
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "pot(上次结果)"
            rc, out = run_john(hash_path, pot_path,
                               ["--markov=100", "--max-length=8"],
                               "Markov 统计攻击（level=100, ≤8 位）",
                               left(), "markov", format_name, enc, speed_ref)
            pw = read_john_pot(hash_path, pot_path, format_name)
            if pw:
                return pw, "Markov"
        if not skip_flags.get("incremental"):
            for mode_name, maxlen in (("LowerNum", 8), ("Digits", 10)):
                pw = read_john_pot(hash_path, pot_path, format_name)
                if pw:
                    return pw, "pot(上次结果)"
                rc, out = run_john(hash_path, pot_path,
                                   ["--incremental=" + mode_name,
                                    "--max-length=" + str(maxlen)],
                                   "Incremental(%s) ≤%d 位" % (mode_name, maxlen),
                                   left(), "inc_" + mode_name.lower(), format_name,
                                   enc, speed_ref)
                pw = read_john_pot(hash_path, pot_path, format_name)
                if pw:
                    return pw, "Incremental(%s)" % mode_name
    return None, None


# ----------------------------------------------------------------------------
# 6. 掩码 keyspace 估算（用于进度提示）
# ----------------------------------------------------------------------------
CHARSET_SIZES = {
    "?l": 26, "?u": 26, "?d": 10, "?s": 33, "?a": 95,
    "?h": 16, "?H": 16, "?b": 256, "?B": 128,
}


def is_digit_mask(m):
    """掩码是否完全由 ?d 占位符组成（如 ?d?d?d）"""
    return len(m) >= 2 and len(m) % 2 == 0 and all(
        m[i:i + 2] == "?d" for i in range(0, len(m), 2))


def estimate_mask_size(mask):
    """估算掩码 keyspace（按 ?x 字符集大小乘积；字面字符计 1 种）"""
    size = 1
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            size *= CHARSET_SIZES.get(mask[i:i + 2], 1)
            i += 2
        else:
            i += 1
    return max(1, size)


SPEED_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([KM]?)p/s|(\d+(?:\.\d+)?)\s*([KM]?)c/s")


def capture_speed(text, ref):
    """从 john 输出行提取 p/s 或 c/s 速度，写入 ref['speed']"""
    m = SPEED_RE.search(text)
    if m:
        val = float(m.group(1) or m.group(3))
        unit = (m.group(2) or m.group(4) or "")
        ref["speed"] = val * {"": 1, "K": 1000, "M": 1000000}.get(unit, 1)


def eta_line(keyspace, ref):
    """生成 keyspace/ETA 提示行"""
    s = "keyspace≈%.3g" % keyspace
    if ref.get("speed"):
        sec = keyspace / ref["speed"]
        s += "，参考上一阶段速度 %.0f/s → 预计 %s" % (ref["speed"], fmt_dur(sec))
    return s


# ----------------------------------------------------------------------------
# 7. 验证与结果
# ----------------------------------------------------------------------------
def verify_password(zip_path, password):
    """用 Python zipfile 真实解密验证密码（含校验位检查）。返回 True/False"""
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        return False
    infos = zf.infolist()
    if not infos:
        return False
    try:
        with zf.open(infos[0], pwd=password.encode("utf-8")) as f:
            f.read(1)
        return True
    except Exception:
        return False


# ----------------------------------------------------------------------------
# 8. 主流程
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="ZIP 压缩包密码一键恢复（整合 hashcat + John the Ripper）")
    ap.add_argument("--target", default=DEFAULT_TARGET, help="目标 zip 路径")
    ap.add_argument("--result-dir", default=DEFAULT_RESULT_DIR, help="结果输出目录")
    ap.add_argument("--dict", default=None, help="附加自定义字典文件")
    ap.add_argument("--masks", default="?d?d,?d?d?d,?d?d?d?d,?d?d?d?d?d,?d?d?d?d?d?d,?d?d?d?d?d?d?d,?d?d?d?d?d?d?d?d",
                    help="掩码列表（逗号分隔；纯数字掩码会合并为一次 john/hashcat 增量调用，覆盖最短~最长）")
    ap.add_argument("--ladder", choices=["minimal", "standard", "full"], default="standard",
                    help="攻击阶梯：minimal=字典+规则；standard=+混合掩码+掩码；full=+PRINCE/Markov/Incremental")
    ap.add_argument("--rules", default=JOHN_RULESET_DEFAULT,
                    help="john 规则集（john.conf [List.Rules:xxx]，默认 All）")
    ap.add_argument("--hashcat-rules", default=HASHCAT_RULES, help="hashcat 规则文件（默认 rules/best66.rule）")
    ap.add_argument("--skip-mask", action="store_true", help="跳过掩码攻击")
    ap.add_argument("--skip-rules", action="store_true", help="跳过规则攻击")
    ap.add_argument("--skip-hybrid", action="store_true", help="跳过混合掩码")
    ap.add_argument("--skip-prince", action="store_true", help="跳过 PRINCE")
    ap.add_argument("--skip-markov", action="store_true", help="跳过 Markov")
    ap.add_argument("--skip-incremental", action="store_true", help="跳过 Incremental")
    ap.add_argument("--no-checksum-pass", action="store_true", help="跳过 17230 校验和快速预跑")
    ap.add_argument("--time-limit", type=int, default=0, help="总攻击时长上限（秒），0=不限")
    ap.add_argument("--python-only", action="store_true", help="只用纯 Python 引擎")
    ap.add_argument("--info", action="store_true", help="只解析哈希、打印引擎计划后退出")
    ap.add_argument("--clean-temp", action="store_true", help="完成后删除临时目录（含哈希/字典/pot）")
    args = ap.parse_args()

    ensure_dir(args.result_dir)
    ensure_dir(TEMP_DIR)

    target = os.path.abspath(args.target)
    if not os.path.isfile(target):
        print("错误: 目标压缩包不存在: %s" % target)
        sys.exit(1)

    t0 = time.time()
    print("=" * 68)
    print("ZIP 密码恢复工具 v2（整合 hashcat + John the Ripper，文档驱动优化）")
    print("目标: %s" % target)
    print("结果目录: %s" % args.result_dir)
    print("=" * 68)

    # 1. 提取哈希
    fmt, full_hash, meta = extract_zip_hash(target)
    if not meta.get("parse_ok"):
        log("警告: 哈希头解析失败，将按原始哈希文件交给引擎（john 自动识别）")

    plan = choose_engine(meta)
    if args.info:
        print("\n==== 哈希信息 ====")
        print("格式: %s  条目数: %s  校验字节: %s" % (
            meta["format"], meta.get("cnt", "?"), meta.get("chk_bytes", "?")))
        if meta.get("entries"):
            for i, e in enumerate(meta["entries"]):
                print("  条目%d: type=%s comptype=%s complen=%s declen=%s" % (
                    i, e.get("type"), e.get("comptype"),
                    fmt_bytes(e.get("complen", 0)), fmt_bytes(e.get("declen", 0))))
        print("引擎计划: hashcat 模式=%s  17230校验和预跑=%s  john格式=%s" % (
            plan["hashcat_modes"] or "无",
            plan["checksum_ok"] and not args.no_checksum_pass,
            plan["john_format"]))
        print("17230 说明: 校验和哈希走 hashcat 17230（无 320KB 限制，多条目包触发，命中经真实解密复验）")
        return

    hash_path = os.path.join(TEMP_DIR, "target.hash")
    write_file(hash_path, full_hash)
    log("哈希已写入: %s（%s）" % (hash_path, fmt_bytes(len(full_hash))))

    masks = [] if args.skip_mask else [m for m in args.masks.split(",") if m]
    john_pot = os.path.join(TEMP_DIR, "john.pot")
    hc_pot = os.path.join(TEMP_DIR, "hashcat.pot")

    # 2. 字典
    dict_path, n_dict = None, 0
    if not args.python_only:
        dict_path, n_dict = make_dict(args.dict)
        log("字典就绪: %d 条候选（%s）" % (n_dict, dict_path))

    # 3. 攻击阶梯
    password = None
    hit_stage = None
    time_limit = args.time_limit or None

    if args.python_only:
        password, hit_stage = crack_pure_python(target, dict_path, masks)
    else:
        # 3.1 hashcat 17230 校验和快速预跑（多文件包）
        if plan["checksum_ok"] and not args.no_checksum_pass:
            try:
                _, chk_hash, _meta = extract_zip_hash(target, checksum_only=True)
                chk_path = os.path.join(TEMP_DIR, "target_check.hash")
                write_file(chk_path, chk_hash)
                log("校验和哈希已生成（hashcat -m 17230 快速预跑）")
                # 预跑只占时间预算的一部分，把剩余预算留给 john 主引擎
                prepass_limit = None
                if time_limit:
                    prepass_limit = max(1, min(60, int(time_limit * 0.3)))
                cands = crack_hashcat(chk_path, 17230, dict_path, masks, hc_pot,
                                      prepass_limit, with_rules=True,
                                      keep_guessing=True,
                                      verifier=lambda pw: verify_password(target, pw))
                for pw in cands:
                    if verify_password(target, pw):
                        password, hit_stage = pw, "hashcat 17230 校验和预跑"
                        break
                    log("17230 候选 %r 未通过真实解密验证（误报），继续检查下一候选" % pw)
                if cands and not password:
                    log("17230 预跑候选均未通过验证，继续完整攻击")
            except Exception as e:
                log("17230 预跑不可用（%s），继续 ..." % e)

        # 3.2 主引擎
        if not password:
            if plan["hashcat_modes"]:
                for mode in plan["hashcat_modes"]:
                    cands = crack_hashcat(hash_path, mode, dict_path, masks, hc_pot,
                                          time_limit,
                                          with_rules=not args.skip_rules,
                                          verifier=lambda pw: verify_password(target, pw))
                    for pw in cands:
                        if verify_password(target, pw):
                            password, hit_stage = pw, "hashcat -m %d" % mode
                            break
                        log("hashcat -m %d 候选 %r 未通过验证，继续" % mode)
                    if password:
                        break
            # 3.3 john 主引擎（大条目/多条目/兜底）
            if not password and plan["john_format"]:
                if plan["hashcat_modes"]:
                    log("hashcat 未命中，回退 john %s ..." % plan["john_format"])
                skip_flags = {
                    "dict": False, "rules": args.skip_rules,
                    "hybrid": args.skip_hybrid, "mask": args.skip_mask,
                    "prince": args.skip_prince, "markov": args.skip_markov,
                    "incremental": args.skip_incremental,
                }
                pw, stage = crack_john(
                    hash_path, dict_path, masks, john_pot, args.rules,
                    time_limit, ladder=args.ladder,
                    format_name=plan["john_format"], skip_flags=skip_flags)
                if pw and verify_password(target, pw):
                    password, hit_stage = pw, "john %s（%s）" % (plan["john_format"], stage)
                elif pw:
                    log("john 候选 %r 未通过验证，继续" % pw)
            # 3.4 多条目、各文件密码不同时的逐条目回退
            if (not password and fmt in ("pkzip2", "pkzip1") and meta.get("parse_ok")
                    and meta["cnt"] > 1):
                log("多条目包整体攻击未命中，尝试逐条目破解（zip2john -o，处理各文件密码不同）")
                try:
                    names = []
                    zf = zipfile.ZipFile(target)
                    for i in zf.infolist():
                        if (i.flag_bits & 0x1) and i.filename not in names:
                            names.append(i.filename)
                    for i, name in enumerate(names):
                        if time_limit and time.time() - t0 > time_limit:
                            log("  已达时间上限，停止逐条目回退")
                            break
                        per_file = os.path.join(TEMP_DIR, "entry_%d.hash" % i)
                        rc, out = run_cmd([ZIP2JOHN_EXE, "-o", name, target])
                        m2 = re.search(r"(\$pkzip2\$.*?\*\$\/pkzip2\$)|\$zip2\$.*?\*\$\/zip2\$", out, re.S)
                        if not m2:
                            log("  条目%d(%s) 哈希提取失败，跳过" % (i, name))
                            continue
                        write_file(per_file, m2.group(0))
                        log("  条目%d(%s): 提取成功，john 字典+规则攻击 ..." % (i, name))
                        pw, stage = crack_john(
                            per_file, dict_path, [], john_pot, args.rules,
                            time_limit, ladder="minimal",
                            format_name=plan["john_format"],
                            skip_flags={"hybrid": True, "mask": True,
                                        "prince": True, "markov": True,
                                        "incremental": True})
                        if pw and verify_password(target, pw):
                            password, hit_stage = pw, "john 逐条目(条目%d) %s" % (i, stage)
                            break
                except Exception as e:
                    log("逐条目回退异常: %s" % e)

    # 4. 验证 + 输出
    if password:
        if verify_password(target, password):
            log("密码已验证（zipfile 真实解密成功）")
        else:
            log("警告: 引擎报告的密码无法通过真实解密验证，结果不可靠")
            password = None
    if not password:
        print("\n未能在当前攻击集内找到密码。可尝试：")
        print("  1) 提供更大字典: --dict your_wordlist.txt")
        print("  2) 更全面阶梯:   --ladder full")
        print("  3) 自定义掩码:   --masks '?l?l?l?l?l,?u?d?d?d?d?d?d'")
        print("  4) 延长时限:     --time-limit 3600")
        sys.exit(2)

    # 写结果
    pw_path = os.path.join(args.result_dir, "password.txt")
    log_path = os.path.join(args.result_dir, "crack_report.log")
    write_file(pw_path, password + "\n")
    lines = [
        "目标: %s" % target,
        "哈希格式: %s" % fmt,
        "条目数: %s" % meta.get("cnt", "?"),
        "命中阶段: %s" % (hit_stage or "?"),
        "引擎: %s" % ("纯Python" if args.python_only else
                     "hashcat + john（自动）"),
        "密码: %s" % password,
        "验证: 通过（zipfile 真实解密成功）",
        "耗时: %.1f 秒" % (time.time() - t0),
    ]
    write_file(log_path, "\n".join(lines) + "\n")
    print("\n" + "=" * 68)
    print("破解成功！")
    print("密码: %s" % password)
    print("命中阶段: %s" % (hit_stage or "?"))
    print("结果已写入: %s" % pw_path)
    print("=" * 68)

    if args.clean_temp:
        import shutil
        shutil.rmtree(TEMP_DIR, ignore_errors=True)
        log("已清理临时目录: %s" % TEMP_DIR)


def crack_pure_python(zip_path, dict_path, masks):
    """纯 Python 字典 + 数字/小写字母小掩码攻击（不依赖外部工具，速度较慢）。"""
    log("步骤: 纯 Python zipfile 逐候选解密（较慢，仅建议小规模字典）")
    zf = zipfile.ZipFile(zip_path)
    infos = [i for i in zf.infolist()]
    if not infos:
        return None, None
    info = infos[0]

    def try_pw(pw):
        try:
            with zf.open(info, pwd=pw.encode("utf-8")) as f:
                f.read(1)
            return True
        except Exception:
            return False

    candidates = []
    if dict_path:
        candidates.extend(ln.strip() for ln in read_file(dict_path).splitlines() if ln.strip())
    for m in masks:
        if is_digit_mask(m):
            n = len(m) // 2
            for tup in itertools.product("0123456789", repeat=n):
                candidates.append("".join(tup))
        elif set(m.replace("?", "")) == set("l") and m.count("?l") <= 4:
            n = m.count("?l")
            import string
            for tup in itertools.product(string.ascii_lowercase, repeat=n):
                candidates.append("".join(tup))
    t0 = time.time()
    for i, pw in enumerate(candidates):
        if try_pw(pw):
            return pw, "纯Python"
        if i and i % 100000 == 0:
            log("  已尝试 %d 个, 速率 %.0f/s" % (i, i / (time.time() - t0)))
    return None, None


if __name__ == "__main__":
    main()
