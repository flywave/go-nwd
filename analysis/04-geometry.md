# NWD 几何层（C4 — Fragment / 几何块容器 / 顶点与索引集）

> 证据级别：E2 静态分析（TNW_Db.tx）。锚点：
> `OdNwGeometryCompressStreamLoader::parseStream@0xd3c0d6`、
> `OdNwFragmentReader::readElement@0xc5cac6`、
> `OdNwGraphicVertexSetReader::{readElement@0xc26590,readVertices@0xc26e80,readIndexes,readBits,readIndexTable}`、
> `OdNwGraphicTriangleSetReader::readElement@0xc67ff2`、
> 源文件 `NwCompressedGeometryWriteCommon.cpp`、`NwGeomBlockData.cpp`。

## §1 几何子系统总览

```
Partition 流对象图
  ├─ Fragment(typeID 13)               # 几何实例：几何索引 + 变换 + 外观
  │     └─ 经 geometryIndex 引用
  ├─ GraphicGeometryRef(typeID 93)     # 几何引用（尺寸/包围盒 + 转向几何集）
  └─ 几何集对象（Vertex/Normal/TexCoord/Color/Triangle/Line/Point Set）

GeometryCompress 流（NwStreamType 6）
  = Blowfish 加密的「几何块」容器 → 每块内含上述几何集对象流
```

## §2 GeometryCompress 流容器（N23，观察级）

`parseStream@0xd3c0d6`：

```
整个流按 8 字节块 Blowfish-ECB 解密（密钥 sGeometryCompressKey@0x16ee400，32B）
解密后（OdFlatMemStream）：
  i32 blockCount
  每块： i32 blockSize + blockSize 字节 + u32 NwAdler32 校验
  块内容 = 几何集对象流（ObjectReader 信封，同 M3）
```

- 密钥（rodata 观察级）：
  `f1fbf239dbb788497ae7459fa3f90e8ffa5ab983acecbf66491df232838d6e6b`
  （**与 M2 TOC 封印同值**，属 ODA 固定内置密钥）
- `OdNwGeometryCompressSettings` 暴露位：precision、vertex/normal/texcoord/color/
  indices/lengthsCompressed、各 precisionReduced(+flags)（E1 头 + E2 getter）
- 块计数/每块布局为夹具对齐；真实样例定案（U13）

## §3 顶点集（GraphicVertexSet，typeID 60）（N24）

`readElement@0xc26590` 经 `GeometryCompressSettings.getGeometryVertexCompressed()` 双分叉：

**未压缩路径**（本实现）：
```
i32 vertexCount
vertexCount × (f32 x, f32 y, f32 z)     # OdGePoint3d
```
（`readVertices` 中 count→reserve→逐点 readFloat×3→push_back）

**压缩路径**（readIndexes/readBits/readIndexTable + fillPoint3dArrayByIndexes）：
- 位打包量化 + 索引表 + 精度还原（坐标精度由 settings 决定）
- 结构复杂，需真实样例（U12）

## §4 三角形/线/点集（62/94、81/95、80/96）

- `OdNwGraphicTriangleSetReader::readElement@0xc67ff2`：
  建 `GraphicGeometryRef` → `readUserData` → 调 `GraphicTriangleSetElementReader`（94）
  → `PartitionStreamContext::addGeometry` 注册
- Element 读取器以嵌套 `readObject`（引用 Vertex/Normal/TexCoord/Color 集）
  + `readIndexes`（位打包索引）为主
- 未压缩索引路径 = 线性 uint 索引数组；压缩路径同 U12

## §5 光照/法线/颜色/纹理坐标集

| Set | typeID | 要点 |
|---|---|---|
| ColorSet | 58 | `readColors(stream, OdArray<uint32>&, u8)`（u8 = 通道宽度） |
| NormalSetFloat | 59 | f32 法线三元组 |
| NormalSetShort | 100 | i16 量化法线 |
| TexCoordSet | 61 | `readTexCoords` → OdGePoint2d（f32×2） |
| LineSet | 81 | 线顶点/索引 |
| PointSet | 80 | 点顶点 |

## §6 Fragment（typeID 13）结构（N25，flag/version 门控；部分）

`readElement@0xc5cac6`：11 个 fragment flag 位 × 8 处 format-version 门控，
可选字段包括：
```
align
f64 traversableScale
u32 traversableTris
[flag] u32 …
[门控×8] …
u32 (fragment flags / geometry index?)
readObject (变换 14–17 / 几何引用 93)
u8 primitives
readObject RunPath（路径链接）
double … / transform override
```
精确字段序与位义 → 真实样例（U14）。go-nwd M4 先取稳定字段：
`geometryIndex`、`transform`（14–17 对象）、`primitives` u8。

## §7 go-nwd M4 实现映射

| SDK | go-nwd |
|---|---|
| GeometryCompress 块容器 | `nwd/geom.go` `DecodeGeometryBlocks`（Blowfish-8B + 块表） |
| VertexSet 未压缩 | `DecodeVertexSet`（i32 count + f32×3） |
| 三角/线/点集（未压缩） | `DecodeIndexList`（count + uint32 索引） |
| Mesh | `Mesh{Vertices,Triangles,Normals,Colors}` |
| Fragment | 文档（U14）；`Object` 保留原始 payload 供后续 |

压缩/位打包几何（readIndexes/readBits）与 Fragment 精确位义待真实样例（U12/U14）。
