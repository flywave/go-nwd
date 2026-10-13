# NWD 属性/CDA 层（C5 — Schema 定义 + 属性对象）

> 证据级别：E1 头文件 + E2 静态分析（TNW_Db.tx）。锚点：
> `OdNwCommonSchemasStreamLoader::{parseStream@0xcf8854,readSchema@0xcf8b76,readConcepts@0xcf8a48,readSchemaField@0xcf8c38,readSchemaStructField@0xcf8fac}`、
> `OdNwPartitionPropsStreamLoader::parseStream@0xce5ca8`、
> `OdNwAttributeReader::readElement`、
> `NwSchemaTypes.h`（E1）。

## §1 属性子系统总览

```
CommonSchemas 流（NwStreamType 39）   → Schema 定义（字段 id/类型/concepts）
PartitionProps 流（NwStreamType 1）   → 节点属性块（按节点索引，ObjectReader 信封）
Partition 流对象图内联 Attributes      → 节点直接携带的属性对象
```

## §2 字段类型枚举（E1，`NwSchemaTypes.h`，权威）

| 值 | 类型 |
|---|---|
| 0 | DOUBLE |
| 1 | GUID |
| 2 | INT32 |
| 3 | BOOLEAN |
| 4 | STRING |
| 20 | STRUCT |
| 21 | VECTOR |
| 0xFFFF | UNKNOWN |

## §3 CommonSchemas 流（N27）

`parseStream@0xcf8854`：读 schema 公共字段（readString×5）→ `i32 schemaCount`
→ 逐 schema `readSchema`；对齐门控按 context alignment（enum0=4/enum1=8）。

`readConcepts@0xcf8a48`（观察级，确证）：
```
i32 count
count × readString<align0>
```
（空指针参数时跳过赋值，仅消费流）

`readSchema@0xcf8b76`：`OdNwSchemaImpl::{getImpl,getSchemaConcepts}`（概念数组装配）。

`readSchemaField@0xcf8c38`：
```
readString → setId
[version gate] readString / readConcepts(getConcepts())
[version gate] readString → setDisplayName
```

`readSchemaStructField@0xcf8fac`：
```
readEnum<NwSchemaFieldType> → setFieldType
readDouble → setValue …（结构字段带内联值）
```

**go-nwd 采用的 Schema 布局**（夹具对齐；真实样例定案 U15）：
```
i32 schemaCount
每 schema： string name · string displayName · concepts · i32 fieldCount
  每 field： string id · string displayName · u32 fieldType · concepts
concepts = i32 count + count×string
```

## §4 属性对象（N28）

`OdNwAttributeReader::readElement`（基类，所有属性共有）：
```
ModelBase（string userName + object→Name className）   # 复用 M3 解码
u32 attrFlags
[flag] setIsDynamic / isRenderAttribute
```

已知属性类型（typeID → payload，E2 观察）：

| ID | 类型 | payload（在 ModelBase+attrFlags 之后） |
|---|---|---|
| 66 | UInt64Attribute | u64 |
| 70 | NameAttribute | （字串值，见 name 对象） |
| 76 | TextAttribute | string |
| 79 | URLAttribute | string + u32 |
| 86 | PropertyAttribute | string + u32 + 2×readObject + readData |
| 88 | BinaryAttribute | i32 len + bytes |
| 180 | GuidAttribute | GUID(16B) |

属性对象经对象信封（M3 readObject）出现在 Partition/Props 流；`PropertyAttribute`
为 CDA 主载体（键→值，值可为嵌套属性对象）。

## §5 PartitionProps 流（N29）

`parseStream@0xce5ca8`：
- `OdNwPartitionStream::TBlockParams::getAttr` + `std::tuple<u32,u32,u32>` +
  `accumulate`/`vector<u32>`：**按分区块索引定位属性块**（`resolveBlockForIndex(u32)`）
- `ObjectReaderManager` + `readObject`×2：块内为属性对象信封
- `OdNwLogicalHierarchyStreamLoader::getPartPropsBlocks`：逻辑层次提供块映射

⇒ PartitionProps = 节点索引 → 属性块（块内属性对象序列），与 Partition 树的
`GuidIndex`/节点序对接。

## §6 go-nwd M5 实现映射

| SDK | go-nwd |
|---|---|
| NwSchemaFieldType | `nwd/props.go` `FieldType` 常量 |
| readConcepts | `decodeStringList`（i32 + 字符串数组） |
| Schema/Field 布局 | `DecodeSchemas`（夹具对齐 U15） |
| Attribute 基类 | `decodeAttribute`（ModelBase + attrFlags + 按类型值） |
| 属性对象 | 扩展 `decodePayload`：类型 66/70/76/79/86/88/180 |

Schema 顶层计数与字段序、PropertyAttribute 嵌套值编码待真实样例（U15/U16）。
