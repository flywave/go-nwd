# NWD 容器格式总纲（C1 — 文件头/签名/版本/StreamSplitter/TOC）

> 证据级别：E2 静态分析（TNW_Db.tx，观察级为主；个别字段标注推断）。
> 反编译锚点：`OdNwStreamSplitter::Load@0xbd34b4`、`readStreamConfig@0xbd2da6`、
> `LoadOld@0xbd23a2`、`NwInflate@0xbd98ba`、源文件 `BimNv/Source/IO/NwStreamSplitter.cpp`。

## §1 文件头签名（三种模式）

Load 读取文件起始 **52 字节（0x34）** ASCII，取 **left(48)** 与签名比对（E2 观察）：

| 模式 | 签名（48B 或更长） | rodata 地址 |
|---|---|---|
| ASCII | `#LcUStream-V1.1 ascii double release C lichunka-` | `sFirstSignatureAscii@0x16f2f60`（ctor←`0x115bc08`） |
| Binary/utf8 | `#LcUStream-V1.1 binary double release utf8 navisworks:`（54B） | `0x115bb98` |
| Binary/lichunk | `#LcUStream-V1.1 binary double release C lichunk-` | `0x115bbd0` |

签名词法（readStreamConfig 逐词解析，E2 观察）：

```
#LcUStream-V1.1  <binary|ascii>  <double|single>  <release|debug>  <utf8|C>  [尾词]
```

**头部磁盘形态**：Load 始终读 52B 并比对 left(48)；因此三种模式的**文件头**
统一为「48B 签名体 + ASCII 版本数字」。binary-navisworks 模式的 48B 体是完整
54B 串的前缀 `#LcUStream-V1.1 binary double release utf8 navis`（N13a）；
完整 54B 串（含 `navisworks:`）是**尾块签名行**的词法形态（readStreamConfig 消费）。

尾词（按模式）：
- ascii+C → `lichunka-`（无数字后缀）
- binary+C → `lichunk-`
- binary+utf8 → `navisworks:<N>`（N 为十进制数，readStreamConfig 解析入 config+0x10）
- 另见 `lcodapi-<N>` 变体（同样写 config+0x10）
- `lizlib` 词存在 → config+0x14 字节=1（E2：find("lizlib")==0 时 `movb $1, 0x14(cfg)`）

### 版本号

签名 48B 之后紧跟 **ASCII 十进制版本数字**（Load：`OdString(buf+0x30)` → `Od_strtoint` → `Splitter+0x14`）。
版本门控（E2 观察）：

```
version > 8  → 错误(3)
version ≤ 1  → 错误(3)
version ≤ 7  → LoadOld 路径
version == 8 → 新路径（本文档主述）
```

⇒ **容器格式版本**（1..8）独立于 Navisworks 应用版本（`NwFormatVersion` NW-1..NW_2027）。

## §2 v8 文件总体布局（E2 推断+观察）

```
偏移              内容
──────────────    ─────────────────────────────────────────────
0                 52B ASCII 头：48B 签名 + 版本数字 + 填充/NUL
52                主负载：命名逻辑流的 chunk 序列（压缩细节 M2）
…
P = F-N-0x44      尾块起点（大小 N）：
                  ├─ ASCII 签名行（同词法，readStreamConfig 重新解析）
                  └─ zlib 压缩的 TOC（NwInflate，M1 解析目标）
P+N               8B 间隙（语义未定，推断：对齐/校验）
P+N+8             8B Int64 = N（尾块压缩尺寸，footers 尺寸锚）
P+N+16            52B 页脚 = 文件头 52B 的副本（Load 比对验证）
F = P+N+0x44      EOF
```

其中 `F`=文件大小，`N`=页脚前 Int64（`seek(fileSize-0x3c)` 处读取，存 `Splitter+0x20`）。
`0x44=68=8(间隙)+8(N)+52(页脚)`。

**尾块内部对齐**（N13b，E2 观察）：readStreamConfig 解析完签名词后，
`pad = (−consumed) & 7` 补齐到 **8 字节边界**（相对尾块起点），随后才是
zlib 流（`vtable+0xa0` 读掉 pad 字节，@0xbd32af–0xbd32ed）。

**页脚验证**（E2 观察）：读 `fileSize-0x3c` 处 Int64 → N；再读随后 52B 与文件头比对（`operator!=` 不等→错误 4）；
随后 `seek(fileSize-N-0x44)` 回到尾块。

## §3 TOC（尾块 zlib 解压后）结构（E2 观察）

```
rdInt32                         # 字段 A（推断：流数量或版本）
rdInt32                         # 字段 B
循环（数量=A 或 B，M2 定案）：
  rdInt32 nameLen
  nameLen × u8                  # 流名（UTF-8/ASCII，如 "LcOpNwdPartition"）
  NwAdler32(name)               # 名字 Adler-32 校验
  NwStreamCommon::readStreamBitfield   # 位域
  NwStreamCommon::alignPointer<1>      # 对齐（模板参数 1，实际粒度待定案）
  rdInt64                       # 字段 C（推断：chunk 偏移或大小）
  rdInt64                       # 字段 D（推断：另一尺寸/偏移）
  rdInt32                       # 字段 E（推断：chunk 数）
  …（后续字段+多次 NwAdler32，循环尾 push_back 到 OdArray<NwSubStreamDef>）
```

`NwSubStreamDefBase` 构造清零布局（E2 观察）：`+0x18:u32, +0x20:u64, +0x28:u64, +0x30:u32, +0x34:u32`；
`NwSubStreamDef` 在 `+0x38` 挂 `OdArray<OdStreamBuf>`（chunk 缓冲，仅内存态）。
流名→`NwStreamType::Enum` 映射见 `00-sdk-inventory.md` §2。

## §4 压缩

- TOC 与 chunk 均为 **标准 zlib**（`oda_z_inflate` PLT：`inflateInit_/inflate/inflateEnd`）⇒ Go `compress/zlib` 直接可用（E2 观察）
- `NwAdler32` = 标准 Adler-32（zlib 同族校验）
- `OdNwCompressedStream{Single,Multi}Chunk`：负载 chunk 包装；MultiChunk 支持 MT（`createMTInstance`）

## §5 TNwStreamConfig 字段映射（E2，部分推断）

| 偏移 | 类型 | 语义 | 证据 |
|---|---|---|---|
| +0x00..+0x0f | 4×u32 | mode/precision/build/encoding 的位标志（推断； ctor 清零） | ctor@0xb2f674 |
| +0x10 | u32 | `navisworks:<N>`/`lcodapi-<N>` 的 N | readStreamConfig@0xbd31a0/0xbd320a |
| +0x14 | u8 | `lizlib` 标志 | readStreamConfig@0xbd327e |

注意：版本号写在 **Splitter+0x14**（u32），与 config 对象（Splitter+0x2c）不重叠。

## §6 旧路径 LoadOld（v2–7，未展开）

`LoadOld@0xbd23a2`：低版本容器，本里程碑仅识别版本并返回 `ErrUnsupportedVersion`。
展开条件：出现 v2–7 真实样本或业务需要。

## §7 加密

`OdNwStreamSplitter::setPassword@0xbd0df6` 存在 ⇒ 支持口令文件。
首期 go-nwd：检测到加密位（M2 定案检测点）时报 `ErrEncrypted`，不解密。

## §8 合成夹具构造规则（M1 测试用）

最小合法 v8 文件（空 TOC）——**已由 `internal/nwstream.BuildSyntheticV8` 实现**：

```
[0:52)   48B 签名体 + '8' + NUL 填充
[52:P)   主负载（测试任意字节）
[P:...)  尾块 = 签名行(48B+"\n") + 8B 对齐填充 + zlib(TOC)
[P+N:...] 8B 间隙(零) + 8B LE Int64(N) + 52B 头副本
```

TOC 合成：`u32 countA + u32 countB + n×[u32 len][name][u32 adler][u32 bitfield][u64 A][u64 B][u32 C]`。
与真实样例的偏差记 findings N/U 系列（优先 U1/U4）。
