# ODA BimNv SDK 模块地图（C0 盘点）

## 证据源

- SDK 根：`go-dgn/ODA-Parse-DWGs-main/ODAToolkit/`（ODA 2026 版权头）
- E1：`BimNv/Include/**`（~200 个 `Nw*.h` 公共 API）、`Exchange/Exports/NwdExport/`（C++ 源码）
- E2：`bin/lnxX64_11dll/TNW_Db.tx`（32MB，ELF x86-64，**not stripped**，85,998 符号 / 13,875 T 符号）
- E2：`archives/Visualize_lnxX64_11dll.lic/bin/lnxX64_11dll/Nw2Visualize.tx`（导入插件 2.7MB）
- E2：`archives/Visualize_lnxX64_11dll.lic/bin/lnxX64_11dll/Visualize2Nwd.tx`（导出插件 1.4MB）
- E2 辅助：`bin/lnxX64_11dll/{NwdExport,NwDumper,NwGeom2Shell,NwExchangeFactory}.tx`

## §1 模块地图

| 模块 | 职责 |
|---|---|
| **TNW_Db.tx** | **BimNv 核心库**：NWD 文件读写（OdNwStreamSplitter/OdNwCompressor）、对象模型（OdNwDatabaseImpl）、31 种流 Loader/Saver、对象级 Reader/Writer |
| Nw2Visualize.tx | Visualize 导入插件（消费 OdNw* 公共 API，不含格式解析） |
| Visualize2Nwd.tx | Visualize 导出插件（OdTv2NwdCopier → OdNwDatabase API） |
| NwdExport.tx | Exchange 导出模块（源码在 `Exchange/Exports/NwdExport/`） |
| NwDumper.tx | 对象转储扩展（Extensions/NwDumper 源码） |
| NwGeom2Shell.tx | 几何→Shell 转换 |

## §2 TNW_Db.tx 内部架构（E2 符号级）

### 文件读取管线

```
OdNwDatabaseImpl::readFile@0x10021ae
 └─ OdNwStreamSplitter::Load@0xbd34b4          # 容器解析（v8 新路径）
      ├─ 读 52B ASCII 头 → 比对 sFirstSignatureAscii（left(48)）
      ├─ 版本门控：>8 错误 / ≤1 错误 / ≤7 LoadOld / ==8 新路径
      ├─ 新路径：seek(fileSize-0x3c) → rdInt64=N → seek(fileSize-N-0x44)
      │    ├─ readStreamConfig@0xbd2da6        # 尾块签名词法（binary/ascii…lizlib）
      │    └─ OdNwCompressor::NwInflate        # 尾块 zlib → TOC
      │         └─ rdInt32×2 头 + 每流：
      │              readStreamNameString(len+bytes) → NwAdler32(name)
      │              readStreamBitfield → align → rdInt64×2 → rdInt32…
      └─ OdNw*StreamLoader::parseStream ×31    # 按流名分发
 └─ OdNw*Reader::readElement（ObjectReaderManager）# 对象级读取
```

### 压缩层

- `OdNwCompressor::NwInflate@0xbd98ba` → 调用 **`oda_z_inflateInit_/oda_z_inflate/oda_z_inflateEnd`（标准 zlib）**
- `OdNwCompressedStream{SingleChunk@,MultiChunk@}`：chunk 级压缩流
- `NwAdler32`：标准 Adler-32 校验

### 流类型枚举（makeStreamSaver 模板实例提取，36 类）

| ID | 流 | ID | 流 |
|---|---|---|---|
| 1 | PartitionProps | 24 | Stats |
| 2 | CurrentViewElement | 25 | Publish |
| 3 | DBCacheChunk | 27 | SavedViewsElement |
| **4** | **Fragments** | 28 | SelectionSet |
| **5** | **Geometry** | 29 | SpeedElement |
| **6** | **GeometryCompress** | 33 | TimeLinerSimulateDuration |
| **7** | **LogicalHierarchy** | 34 | TimeLiner |
| **8** | **Partition** | **39** | **CommonSchemas** |
| **10** | **SpatialHierarchy** | **40** | **FileInfoChunk** |
| 11 | ScenePropsChunk | 41 | XRefTable |
| 14 | BackgroundElement | 42 | PropertyOverride |
| 15 | ClashElement | 43 | HyperlinksOverride |
| 16 | CullingElement | 45 | SceneSet |
| 17 | DBDatabaseLinksElement | 46 | PathMap |
| 19 | GuidStore | 52 | ShadOverrides |
| 20 | HeadlightElement | 54 | MaterialElement |
| 21 | LightsElement | 58 | GridElement |
| 23 | SharedNodes | 59 | DBDatabaseProperty |
| | | 60 | Cached |
| | | 62 | SavedAnimations |

### 内部流名（UTF-32LE rodata 提取，getStreamNameByType 表）

`LcOaPartitionProps`、`LcOpCurrentViewElement`、`LcOpDBCache`、`LcOpNwdFragments`、
`LcOpNwdGeometry`、`LcOpNwdGeometryCompress`、`LcOpNwdLogicalHierarchy`、`LcOpNwdPartition`、
`LcOpNwdSerial`、`LcOpNwdSpatialHierarchy`、`LcOpOdyScenePropsChunk`、`LcOpBackgroundElement`、
`LcOpClashElement`、`LcOpCullingElement`、`LcOdpDBDatabaseLinksElement`、
`LcOpCurrentAnimationElement`、`LcOpGuidStore`、`LcOpHeadlightElement`、`LcOpLightsElement`、
`LcOpNwdSharedNodes`、`LcOpSharedNodes`、`LcOpNwdStats`、`LcOpNwdPublish`、
`LcOpPlanViewElement`、`LcOpSavedViewsElement`、`LcOpSelectionSetsElement`、
`LcOpSpeedElement`、`LcOpToolElement`

### 关键源文件名（strings，反编译定位锚点）

`BimNv/Source/IO/NwStreamSplitter.cpp`、`NwCompressedGeometryWriteCommon.cpp`、
`NwGeomBlockData.cpp`、`NwFileInfoWriter.cpp`、`NwGraphicMaterialWriter.cpp`、
`NwPropertyLevel.cpp`、`NwObjMatrix.cpp`

## §3 对象模型（E1 头文件）

- **Database**：`OdNwDatabase`（readFile/writeFile/getModels/getSheets/getUnits…）
- **模型树**：`OdNwModel` → `OdNwPartition`(OdNwModelItem) → 子 Item；Spatial/Logical 双层次索引
- **几何**：`OdNwGeometry{Shell,LineSet,PointSet,Text,Circle,Cylinder,External}`；
  `OdNwFragment`（GeometryId+Transformation+Material+isSolid）；
  GeometryCompress 带坐标/颜色精度压缩标志（OdNwGeometryCompressSettings）
- **属性**：`OdNwCommonSchema`（Boolean/Double/Int32/String/Guid/Struct 字段）+
  `OdNwPropertyAttribute`/`OdNwCategory`/`OdNwDataProperty`
- **版本**：`NwFormatVersion` NW_UNSUPPORTED..NW_2027（15 档）；
  `NwFileType` kNwd=0/kNwc=1/kNwf=2

## §4 与 go-nwd 实现的映射

| SDK 层 | go-nwd 目标 |
|---|---|
| OdNwStreamSplitter::Load | `internal/nwstream`（签名+footer+TOC） |
| oda_z_inflate | Go `compress/zlib` |
| NwSubStreamDef 目录 | `nwd.Metadata.Streams` |
| Partition/Spatial/Logical Loader | M3 `nwd/tree.go` |
| GeometryCompress/Fragments Loader | M4 `nwd/geometry.go` |
| CommonSchemas/PartitionProps Loader | M5 `nwd/props.go` |
| OdNwDatabase 写回 | **不实现**（只读解析） |

## 未知

- TNwStreamConfig +0x00..+0x0f 四个 u32 的字段语义（mode/precision/build/encoding 位？）
- NwSubStreamDef 每流 rdInt64×2/rdInt32 是 offset/size/chunkCount 的对应关系
- 主负载 chunk 的物理布局（M2）
- v2–7 LoadOld 路径（低优先）
- 加密 NWD（setPassword）——首期不支持
