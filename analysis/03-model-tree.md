# NWD 模型树层（C3 — 对象信封 + 类型注册表 + 节点 Schema）

> 证据级别：E2 静态分析（TNW_Db.tx）。锚点：
> `readObject@0xc3b4b2`、`registerObjectReaders@0xc1de9a`、
> `ModelBaseReader@0xc37dc2`、`ModelItemNodeReader@0xc38cbe`、
> `PartitionNodeReader@0xc47582`、`NameReader@0xc378b8`、
> `readString<0>@0xc31bfe`、`getAlignment@0xc30b48`。

## §1 流级管线（N18）

Partition / SpatialHierarchy / LogicalHierarchy 三个 Loader 的 parseStream 共用：

```
context.stream
 → [有密码时] OdNwCipheredStream::createNew(stream, passwordUTF8)   # Blowfish 口令流
 → OdNwCompressedStreamSingleChunk::createNew(stream)               # 单块 zlib 解压
 → OdNwObjectReaderManager(context)
 → 循环 readObject(result, expectedTypeID) 直到 null/error
```

Partition 流期望根对象 **typeID=0x20=32（PartitionNode）**（parseStream@0xcb3a9e ecx=0x20）。

## §2 对象信封（N19，readObject 定案）

```
u32 marker:
  0        → nil（流尾/空引用），result=0
  1        → 后随 i32 idx：返回 manager.objectVector[idx]（回指已读对象）
  ≥100     → 新对象：vector 下标 = marker−100（先 push 占位再回填）
             后随 u32 typeID ∈ [0,200]（越界→错误 0x27；工厂缺失→0x03）
             后随 payload（由 typeID 对应 reader 解码，内嵌嵌套 readObject）
```

- `readObjectVector`：`u32 count` + count×readObject
- `readSharedObject`：context 版本 >0x1C3(451) 时走 SharedNodesResolver
  （`i32 key` → resolver 查表）；否则同 readObject
- marker−100 的下标语义 = Saver 侧写入「当前对象序号+100」，自描述校验

## §3 类型注册表 NwObjectType（N20，110/201 槽已注册）

`registerObjectReaders` 将 typeID → GOT 槽（invoker 函数指针），
经 .rela.dyn 重定位解出 `readFromStream_OdNwXxxReader` 符号。
**与 M3 相关的关键条目**（全表见 `internal/nwd/objtype_table.go`）：

| ID | Reader | 角色 |
|---|---|---|
| 1 | StaticTreeGroup | 空间树分组 |
| 2 | StaticTreeLeaf | 空间树叶（引用 Fragment） |
| 13 | Fragment | 几何实例（→ M4） |
| 14–17 | ObjTranslation/TransRot/TransRotScale/Matrix | 变换 |
| 22 | GeometryModelItemNode | 几何模型节点 |
| **32** | **PartitionNode** | 分区树根 |
| 31 / 39–41 | Material/Transform/Trans/TransRotation Attribute | 属性 |
| 52 | Name | 显示名对象 |
| **53** | **GroupModelItemNode** | 分组节点（子节点容器） |
| 58–62, 80–81, 94–96 | Graphic ColorSet/NormalSet/VertexSet/TexCoordSet/TriangleSet/PointSet/LineSet(+Element) | 网格数据（→ M4） |
| 70/76/79/86/88/180 | Name/Text/URL/Property/Binary/Guid Attribute | 属性值 |
| 89 | ElementRecord | 元素记录 |
| 106–149/168–179 | Plot* | 2D 图纸（超范围） |

## §4 字符串编码（N21）

`NwStreamCommon::readString<align0>@0xc31bfe`：

```
i32 byteLen
align 4                    # getAlignment(enum0)=4、enum1=8
byteLen × UTF-8 字节        # utf8ToUnicode 内部转换
```

## §5 节点 Schema（观察级；多版本门控 → U10）

### ModelBase 前缀（所有节点共有，`ModelBaseReader`）

```
[string userName]        # readString<0>
[object className]       # readObject → 期望 typeID=52 Name
```

`formatVersion > 0x15(21)` 时进入读取（否则跳过——低版本路径 U10）。

### Name（typeID 52）

```
[string displayName]
[string name]            # 非空则 setName
```

### ModelItemNode（typeID 32/53/22 的中间层）

```
ModelBase 前缀
u32 flags                # 位标志驱动大量可选字段（14 处位测试）
[v > 0xF8(248) 分支]     # 版本门控字段（U10）
u32 guidIndex            # setGuidIndex（v > 0xD6(214) 时另有前置分支）
u32 attributeCount
attributeCount × readObject  # 期望 AttributeProxy 族；nil 终止
```

### PartitionNode（typeID 32）

```
[版本门控预设]
u32 modelType → setModelType
u32 flags → setCompactFragOnce
ModelItemNode 中层
[context 装配：Partition 流根挂入 context；Logical 流挂 rootPartition]
readEnum<NwPartitionUsage> → setUsage
```

### GroupModelItemNode（typeID 53）

= ModelItemNode + 子节点数组（children 读取点在 PartitionNodeReader 的
getChildren 分支；子节点循环经嵌套 readObject，期望 32/53/22 族）。

### StaticTreeGroup/Leaf（typeID 1/2，空间层次）

`readStaticItem(manager, NwTreeItemType, fragmentLookupCallback, item)`：
组/叶递归 readObject；叶引用 Fragment id（回调经 SpatialHierarchy 的
partition tree 解析）。格式细节 → M4 联调（U11）。

## §6 版本体系（澄清）

| 编号 | 含义 | 载体 |
|---|---|---|
| 容器版本 1–8 | StreamSplitter 布局 | 文件头 ASCII（M1） |
| `NwFormatVersion` NW-1..2027 | 应用版本档位（E1 头文件） | — |
| **`NwFormatVersionEx`** | **reader 字段门控版本**（>21/>214/>248/>451…） | context+0x18（读写端经 `readEnum<FormatVersionEx>`，具体注入点 U10） |

## §7 go-nwd M3 实现映射

| SDK | go-nwd |
|---|---|
| readObject 信封 | `nwd/objects.go` ObjectReader（marker/typeID/backref） |
| registerObjectReaders 全表 | `nwd/objtype_table.go`（110 条 typeID→名字） |
| readString | `readString`（i32+UTF-8+align4） |
| ModelBase/Name/ModelItemNode/PartitionNode | `nwd/tree.go` 解码器（高版本路径） |
| 循环 readObject | `WalkObjectStream` |

版本门控（U10）与子节点数组精确格式以夹具先行；真实样本到位后
逐门控校正（同 M1/M2 策略）。
