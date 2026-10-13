# 真实样本字节级校正（C7 — BCCCH BIM Coordination Model）

> 样本：`nwd/testdata/BCCCH_BIM Coordination Model_251024.nwd`
> （25,675,348 字节，Navisworks 2024 发布，`#LcUStream-V1.1 binary double release C lichunk-008`）。
> 本节以真实文件为准，修正 M1/M2 的静态推断。golden 测试：`nwd/real_test.go`。

## §1 文件总布局（修正 N5）

```
[0, 52)            头签名 + 3 位版本 + '\n'  （"…lichunk-008\n"）
[52, N)            主负载：各逻辑流区域（26/27 为 zlib）
[N, F-0x44)        尾块：navisworks 签名行 + 8B 对齐 + zlib(TOC)   ← N=0x187c383，长 653B
[F-0x44, F-0x3c)   8B 间隙
[F-0x3c, F-0x34)   Int64 N（尾块偏移）
[F-0x34, F)        52B 头副本（页脚签名）
```

- **页脚 Int64 是尾块偏移（非尺寸）**：Load 的 seek 目标即该值。
- 尾块签名行是 **navisworks 变体**：`…binary double release utf8 navisworks:451 lizlib\n`
  ⇒ `NwFormatVersionEx=451`（U10 部分收口）。
- zlib 流填满尾块：python `zlib.decompress` 全消费 581B，`eof=True`，**无尾部校验**。

## §2 TOC 记录（修正 N7/N16）

```
i32 magic = -1
i32 count = 27
每流：
  u32 nameLen
  nameLen × u8 (UTF-8, 可带 "cache\" 前缀)
  u32 bitfield
  [align 8]
  i64 offset      ← 绝对文件偏移（单调衔接）
  i64 size        ← 区域长度
  i32 prefix
  i32 suffix
```

- **无存档 name-adler**；**无尾部 Blowfish 校验**（M2 推断过拟合，已废弃）。
- bitfield 实测取值 `0x1 / 0x100 / 0x10000 / 0x1000000 / 0x3000000`（字节对齐标记），
  **非压缩位**；压缩判定改用 **zlib 魔数 `78 9c`**。

## §3 实测流清单（节选）

| 流名 | offset | size | prefix | suffix | zlib |
|---|---|---|---|---|---|
| cache\LcOpNwdGeometryCompress | 52 | 40 | 0 | 0 | 否（加密块） |
| cache\LcOpNwdGeometry | 92 | 21670465 | 4 | 35732 | 是 |
| cache\LcOpNwdPartition | 21670568 | 346 | 0 | 0 | 是 |
| cache\LcOaPartitionProps | 21670914 | 1350390 | 4 | 51 | 是 |
| cache\LcOpNwdFragments | 23600920 | 1735364 | 0 | 0 | 是 |
| LcOpOdyFileInfoChunk | 25674348 | 135 | 0 | 0 | 是 |
| LcOpCommonSchemas | 25674483 | 11 | 0 | 0 | 是 |
| LcOpXRefTable | 25674494 | 133 | 0 | 0 | 是 |

（全 27 条见 golden 测试。）

## §4 对象层验证（N40/N41）

Partition 流 inflate（744B）：
```
64 00 00 00   marker=100 (新对象#0)
20 00 00 00   typeID=32 (PartitionNode)
00 00 00 00   modelType
27 00 00 00   userName 长度 39
"BCCCH_BIM Coordination Model_251024.nwd"
00            (补齐到 4；N37)
65 00 00 00   marker=101
34 00 00 00   typeID=52 (Name)
04 00 00 00   "File"
0d 00 00 00   "LcOaPartition"
...
66 00 00 00   marker=102 → typeID=92 (PublishAttribute)
```

⇒ **M3 对象信封 + ModelBase/ModelName/ModelItem 结构在真实文件上得到验证**；
`readString` 填充在数据之后（N37）。

## §4b Partition 根解码（N42，已落地）

`File.DecodePartitionRoot` 在真实文件上解出：

```
userName    = "BCCCH_BIM Coordination Model_251024.nwd"
className   = "LcOaPartition"
displayName = "File"
modelType   = 0   flags = 0   guidIndex = 0
attrCount   = 1   firstAttrType = 92 (PublishAttribute)
```

字段序 `marker(100) / typeID(32) / modelType / userName / Name(52) / flags / guid /
attrCount` 与 M3 推断完全一致 ⇒ M3 结构在真实文件上验证通过。
`nwdinfo` 输出 `partition_root`。

## §4c PublishAttribute 部分定案（N43，U18）

- payload 实测 **72 字节**（偏移 112→184）
- 首 `i32 = 0xffffffff`；含 i64 时间戳 `0x69043fda`（Unix 2025‑10‑24）
- 与 E2 reader 的 `flags+4串+align8+2时间+4串+explicitName` **未对齐**，
  需按真实字节继续定案（属性基类 ModelBase 是否出现待确认）

## §5 后续（样本已解锁）

| 项 | 内容 |
|---|---|
| U18 | 真实属性类型 payload 全表（PublishAttribute 92 已探：flags+6 串+2 时间+…） |
| U19 | Partition 完整对象图（attrs 序列、子节点、变换） |
| U20 | GeometryCompress 几何块（Blowfish 8B）与 Geometry 流真实内容 |
| U15/U16 | CommonSchemas（11B 真实流）与 PartitionProps 真实布局 |

## §6 实现状态

- `internal/nwstream`：**真实文件全量通过**（N=偏移、无校验、TOC 无 adler、zlib 魔数判定、
  名称 `\` 前缀匹配）。
- `nwd`：字符串填充修正；容器/清单/Metadata；对象层在真实 Partition 上验证到 PublishAttribute。
- golden 测试：`TestRealContainerInventory` / `TestRealStreamInflate`（缺样本自动跳过）。
