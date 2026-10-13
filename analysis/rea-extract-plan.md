# REA 提取清单 — BimNv / TNW_Db.tx（面向 go-nwd M1–M5）

> SDK：`go-dgn/ODA-Parse-DWGs-main/ODAToolkit/bin/lnxX64_11dll/TNW_Db.tx`
> （32MB ELF x86-64，未 strip）。原则：**头文件优先（E1）**，反编译只用于序列化内部。
> 每项交付物：伪代码 + 字段偏移表 + 枚举值表，落入 analysis/ 编号文档。

## P0 容器与 TOC（M1/M2 主战役）

| # | 目标 | 模块/符号 | 要回答的问题 | 解锁 |
|---|---|---|---|---|
| 1 | **TOC 每流记录全字段** | Load 循环 @0xbd3af8–0xbd3d5a | rdInt32×2 头语义（数量?版本?）；每流 rdInt64×2/rdInt32 = offset/size/chunkCount 如何对应；bitfield 位义；align 粒度；循环次数源 | M1 TOC 定案 |
| 2 | **尾块签名行与头一致性** | readStreamConfig 调用点 vs 文件头 | ascii 模式尾块是否也带 lcodapi/lizlib 词？navisworks:N 的 N 语义 | M1 夹具对齐真实 |
| 3 | **主负载 chunk 物理布局** | OdNwCompressedStream{Single,Multi}Chunk::createNew、getStream@0xbd1f10 | chunk 头格式（压缩尺寸/解压尺寸/魔数）；MultiChunk 分块策略；chunk 间排列与 TOC offset 关系 | M2 解压 |
| 4 | **8B 间隙语义** | 尾块 P+N 处 | 对齐？CRC？第二 Int64？ | M1 夹具精确 |
| 5 | **LoadOld（v2–7）** | LoadOld@0xbd23a2 | 旧容器布局；何时需要 | 按需 |

## P1 逻辑流 Loader（M3/M4/M5）

| # | 目标 | 模块/符号 | 要回答的问题 | 解锁 |
|---|---|---|---|---|
| 6 | **Partition 流布局** | OdNwPartitionStreamLoader::parseStream | 模型树节点记录格式（父子/名称/变换/可见性） | M3 树 |
| 7 | **Spatial/LogicalHierarchy** | OdNwSpatial/LogicalHierarchyStreamLoader::parseStream | 与 Partition 的索引关系；条目→模型对象映射 | M3 |
| 8 | **FileInfoChunk** | OdNwFileInfoChunkStreamLoader::parseStream | 文件元数据字段（GUID/作者/时间/单位/模型类型） | M1 元数据增强 |
| 9 | **GeometryCompress 头** | OdNwGeometryCompressStreamLoader | compressionFlags/坐标精度/颜色精度位义；块目录 | M4 |
| 10 | **Fragments 流** | OdNwFragmentsStreamLoader::createStreamLoader | Fragment 记录（geometryId/material/transform）编码 | M4 实例 |
| 11 | **Shell 顶点/索引** | OdNwGeometryShellReader（或 Shell saver 对偶） | 顶点布局（f32/f64/量化）、索引宽度、法线/UV | M4 网格 |
| 12 | **CommonSchemas** | OdNwCommonSchemasStreamLoader::{readSchema,readSchemaField,readConcepts} | schema 树编码（字段类型/名称/concept 分组） | M5 |
| 13 | **PartitionProps** | OdNwPartitionPropsStreamLoader::parseStream | 节点→属性值映射编码 | M5 |
| 14 | **对象读取管理器** | OdNwObjectReaderManager + readFromStream_* | 对象信封（类型标签/尺寸/引用）通用格式 | M3–M5 共用 |

## P2 校验与健壮性（顺手）

| # | 目标 | 模块/符号 | 要回答的问题 |
|---|---|---|---|
| 15 | NwAdler32 校验范围 | TOC 循环内多次 NwAdler32 调用 | 哪些字段参与校验；失败处理 |
| 16 | 加密检测点 | setPassword / Load 分支 | 无口令时的失败签名 |
| 17 | 错误码表 | Load 返回 ebx=2/3/4 | 全部错误条件 |

## P3 几何进阶（go-topo 对接，M4 后）

| # | 目标 | 说明 |
|---|---|---|
| 18 | Geometry vs GeometryCompress 选择 | 何种文件走哪条；双份几何关系 |
| 19 | 外部几何（NwdExport/BrepImport） | OdNwGeometryExternal/SAT 载荷 |
| 20 | 材质/纹理空间 | MaterialElement/TextureSpace 编码 |

## 执行建议

1. **#1 是 M1 收口关键**：无真实样本时用合成 TOC 反推字段；样本到位后第一优先字节级定案。
2. **#3 是 M2 主战役**：chunk 头格式决定解压管线；与 #1 的 offset/size 字段互为验证。
3. #6/#9/#12 头文件字段表先行（E1 便宜），反编译补磁盘布局。
4. 每轮提取结果立即写 findings N 系列 + 对应编号文档。
