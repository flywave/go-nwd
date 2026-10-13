# findings — NWD 结论台账（N 系列）

> 三态：**观察**（E1 头文件 / E2 符号地址直接可见）/ **推断**（多线索综合，待样本验证）/ **未知**。
> 证据引用格式：`E2 符号@地址`、`E1 文件:行`、样例偏移。

## C0/C1 轮（2026-10-13，M0+M1 静态分析）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| N1 | NWD 容器核心实现在 `TNW_Db.tx`（32MB，未 strip）；入口 `OdNwDatabaseImpl::readFile@0x10021ae` → `OdNwStreamSplitter::Load@0xbd34b4` | 观察 | E2 nm/objdump |
| N2 | 文件头为 **ASCII 签名**，三种模式：`…ascii double release C lichunka-` / `…binary double release utf8 navisworks:` / `…binary double release C lichunk-`；Load 读 52B 取 left(48) 比对 | 观察 | E2 Load@0xbd353f `movl $0x34`+left(0x30)；rodata `0x115bc08/0x115bb98/0x115bbd0` |
| N3 | 签名词法：`#LcUStream-V1.1 <binary\|ascii> <double\|single> <release\|debug> <utf8\|C> [尾词]`；尾词含 `navisworks:<N>`/`lcodapi-<N>`/`lizlib` | 观察 | E2 readStreamConfig@0xbd2da6 逐词 iCompare/find；wstr rodata `0x115b9a4..0x115babc` |
| N4 | **容器版本**为签名 48B 后的 ASCII 数字（`Od_strtoint`）；门控：>8/≤1 错误、≤7 LoadOld、==8 新路径。与 `NwFormatVersion`（NW-1..2027）是两套编号 | 观察 | E2 Load@0xbd35e3–0xbd3727 |
| N5 | v8 布局：`[52B 头][主负载…][尾块 N 字节：签名行+zlib TOC][8B 间隙][8B Int64=N][52B 页脚=头副本]`；尾块起点 = fileSize−N−0x44 | 观察（间隙语义推断） | E2 Load@0xbd37e7 rdInt64→+0x20；@0xbd38a6 subq $0x44；@0xbd38e1 seek；@0xbd386f 页脚比对 |
| N6 | **压缩 = 标准 zlib**（`oda_z_inflate*`）；TOC 校验用 `NwAdler32`（标准 Adler-32）⇒ Go `compress/zlib` 直接可用 | 观察 | E2 NwInflate@0xbd98ba 调 `oda_z_inflateInit_/oda_z_inflate/oda_z_inflateEnd`；TOC 循环 `NwAdler32@` 调用 |
| N7 | TOC（尾块 zlib 解压后）：`rdInt32×2` 头 + 每流 `[rdInt32 len][name 字节][Adler32(name)][bitfield][align][rdInt64×2][rdInt32…]`，组装为 `OdArray<NwSubStreamDef>` | 观察（rdInt64/rdInt32 语义推断） | E2 Load@0xbd3af8–0xbd3d5a；readStreamNameString@0xbd08fe |
| N8 | `NwStreamType::Enum` 共 36 类（1..62），关键流：4=Fragments、5=Geometry、6=GeometryCompress、7=LogicalHierarchy、8=Partition、10=SpatialHierarchy、39=CommonSchemas、40=FileInfoChunk | 观察 | E2 makeStreamSaver 模板实例全表 |
| N9 | 内部流名为 UTF-32LE 存储的 `LcOp*`/`LcOa*` 字符串（28 个已提取，见 00-sdk-inventory §2） | 观察 | E2 getStreamNameByType@0xb9883c rodata |
| N10 | `TNwStreamConfig`（21B）：ctor 清零 5×u32+1×u8；+0x10=navisworks/lcodapi 数字；+0x14=lizlib 标志字节。版本号另存 Splitter+0x14(u32) | 观察（+0x00..+0x0f 位义推断） | E2 ctor@0xb2f674；readStreamConfig@0xbd31a0/0xbd327e；Load@0xbd361d |
| N11 | 加密支持存在（`setPassword@0xbd0df6`）；首期 go-nwd 不解密 | 观察 | E2 nm |
| N12 | 对象级读取：每流 Loader（31 种 `parseStream`）+ `OdNw*Reader::readElement`（ObjectReaderManager）两层 | 观察 | E2 nm 全表 |
| N13a | 三种模式的**文件头**统一为「48B 签名体+版本数字」；binary-navisworks 的 48B 体 = 完整 54B 串前缀（`…utf8 nav`）；完整 54B 串属尾块签名行词法 | 观察 | E2 Load left(0x30) 比对宽度；rodata 全串长度 |
| N13b | 尾块签名行结束后按 **8 字节对齐**（`pad=(−consumed)&7`）再进入 zlib 流 | 观察 | E2 readStreamConfig@0xbd32af–0xbd32ed |

## C2 轮（2026-10-13，M2 压缩与 chunk 层）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| N14 | TOC 头：首 `rdInt32` 必须为 **-1**（扩展标记），第二 `rdInt32` = 流数量；非 -1 走错误路径 "Read extensions != -1 !" | 观察 | E2 Load@0xbd3afd；rodata `0x115bb7d` |
| N15 | 每流字段语义定案：`offset(i64)=绝对偏移`、`size(i64)=区域长`、`prefix(i32)=前置切块`、`suffix(i32)=尾裁`、`bitfield 低字节≠0⇒压缩单块`；alignPointer\<1\>=**8 字节对齐** | 观察 | E2 parseStream@0xbd10dd–0xbd13d0 消费端；alignPointer@0xbd51c0 `andl $7` |
| N16 | TOC 完整性：Adler-32 种子 1，滚动覆盖 name→bitfield→offset→size→prefix→suffix（字段值、不含对齐填充）；校验值 = 尾块内 8B **Blowfish-ECB**（固定密钥 `sBlowfishKey@0x16ecfa0`）加密的 u32 双拷贝；不匹配→错误 6 | 观察 | E2 Load@0xbd3a13/0xbd3bf0–0xbd3d3a/0xbd3e66–0xbd3ef1 |
| N17 | 压缩单块经 `copyStream` 原样拷贝后由 `OdNwCompressedStream`/`NwInflate`（zlib）解压；Go 侧 `StreamData` 等价实现 | 观察（Go 路径推断等价） | E2 copyStream@0xbd0e20；NwInflate zlib（N6） |

## C3 轮（2026-10-13，M3 模型树）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| N18 | 三树流 Loader 共用管线：[密码→CipheredStream]→CompressedStreamSingleChunk→ObjectReaderManager→循环 readObject；Partition 期望根 typeID=**32** | 观察 | E2 parseStream@0xcb369c/0xcb3a9e（ecx=0x20） |
| N19 | **对象信封**：`u32 marker`：0=nil；1=回指（后随 i32 idx→objectVector）；≥100=新对象（vector 下标=marker−100，先占位后回填），后随 `u32 typeID`∈[0,200]（工厂表 201 槽，缺失→错 0x03，越界→0x27） | 观察 | E2 readObject@0xc3b4b2–0xc3b6f5 |
| N20 | **NwObjectType 注册表**：registerObjectReaders 注册 110/201 槽；经 GOT+重定位解出全部 `readFromStream_OdNwXxxReader` 名（32=PartitionNode、53=GroupModelItemNode、52=Name、1/2=StaticTreeGroup/Leaf、13=Fragment…全表落 `nwd/objtype_table.go`） | 观察 | E2 registerObjectReaders@0xc1de9a + .rela.dyn/.got |
| N21 | **字符串**：`readString<align0>` = `i32 字节长` + align4 + **UTF-8**（utf8ToUnicode）；getAlignment(0)=4、(1)=8 | 观察 | E2 readString@0xc31bfe；getAlignment@0xc30b48 |
| N22 | 节点 Schema：ModelBase=[string userName][object→Name className]（门控 fv>21）；ModelItemNode 中层=[u32 flags][门控 fv>248 未实现][u32 guidIndex][u32 attrCount + attrs]；PartitionNode=u32 modelType + ModelItem + children + usage enum；Name=[displayName][name]；FormatVersionEx=reader 门控版本（context+0x18，>21/>214/>248/>451 档） | 观察（children 位置夹具对齐 traced 顺序；U10 门控残项） | E2 ModelBase@0xc37dc2、ModelItemNode@0xc38cbe、PartitionNode@0xc47582、Name@0xc378b8、getFormatVersion=manager+0x18 |

## C4 轮（2026-10-13，M4 几何层）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| N23 | **GeometryCompress 流** = 8 字节块 Blowfish-ECB 解密（密钥 `sGeometryCompressKey@0x16ee400`，**与 M2 TOC 密钥同值**）→ `i32 blockCount` + 每块 `i32 size + bytes + u32 adler32`；块内含几何集对象流 | 观察（块计数/布局夹具对齐） | E2 parseStream@0xd3c0d6/0xd3c2f1/0xd3c34a；rodata 0x16ee400 |
| N24 | **顶点集**未压缩路径 = `i32 count + count×(f32 x,y,z)`；压缩路径经 `readIndexes/readBits/readIndexTable + fillPoint3dArrayByIndexes`（位打包量化，由 GeometryCompressSettings 精度控制） | 观察（未压缩定案；压缩结构→U12） | E2 VertexSet readElement@0xc26590、readVertices@0xc26e80 |
| N25 | **Fragment（typeID 13）** = 11 flag 位 × 8 版本门控的可变记录；含 traversableScale(f64)/traversableTris(u32)/primitives(u8)/readObject(变换 14–17 或几何引用 93)/RunPath；精确字段序→U14 | 观察（部分） | E2 FragmentReader@0xc5cac6 |
| N26 | 几何集族：ColorSet(58,readColors+u8 通道宽)、NormalSetFloat(59)/Short(100)、TexCoordSet(61,OdGePoint2d)、LineSet/PointSet/TriangleSet(81/80/62→Element 95/96/94)；TriangleSet 建 GeometryRef + addGeometry 注册 | 观察 | E2 各 Reader readElement |

## C5 轮（2026-10-13，M5 属性/CDA）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| N27 | **NwSchemaFieldType**（E1 权威）：DOUBLE=0/GUID=1/INT32=2/BOOLEAN=3/STRING=4/STRUCT=20/VECTOR=21/UNKNOWN=0xFFFF；`readConcepts` = `i32 count + count×readString`；CommonSchemas parseStream=公共字段+`i32 schemaCount`+逐 schema；readSchemaField=id+[gate] display+concepts；readSchemaStructField=readEnum<FieldType>+readDouble 值 | 观察（E1 定案枚举；流布局夹具对齐 U15） | E1 `NwSchemaTypes.h`；E2 parseStream@0xcf8854、readConcepts@0xcf8a48、readSchemaField@0xcf8c38、readSchemaStructField@0xcf8fac |
| N28 | **属性对象基类** = ModelBase（userName + Name） + `u32 attrFlags`；各类型 payload：66 UInt64Attribute=u64、76 TextAttribute=string、79 URLAttribute=string+u32、86 PropertyAttribute=string+u32+2×readObject+readData、88 BinaryAttribute=i32+bytes、180 GuidAttribute=GUID(16B) | 观察 | E2 OdNwAttributeReader::readElement、各子类 readElement |
| N29 | **PartitionProps 流**：按分区块索引定位属性块（`TBlockParams::getAttr`+`resolveBlockForIndex`+tuple<u32,u32,u32>/accumulate），块内为属性对象信封（ObjectReader）；逻辑层次提供块映射（`getPartPropsBlocks`） | 观察 | E2 parseStream@0xce5ca8 |

## C6 轮（2026-10-13，M6 实例/场景）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| N30 | **版本门控阈值总表**：21/87/214/242/248/451（reader 字面门槛）；Fragment flag 掩码 `>242→&=0x6FFD3FFF`、`≤242→&=0x6FFD3F7F`、`≤87→>>24&0xF`；`NwFormatVersionEx` 流内 rdInt32（档位常量未暴露→U10） | 观察 | E2 FragmentReader@0xc5cac6、ModelBase/ModelItemNode 各门控点 |
| N31 | **StaticTree**：readStaticItem= i32 项 + `function<OdNwFragment*(u32)>` 片段回调 + isShape 分支 → 叶/组递归；readTreeItem 组叶分发 | 观察（部分） | E2 readElement@0xc6033a/0xc62ee2、readStaticItem@0xc603b2 |
| N32 | **变换对象定案**：14 ObjTranslation=3×f64；15 ObjTransRot=3×f64+4×f64 四元数；16 ObjTransRotScale=+f64 缩放；17 ObjMatrix=逐元素 f32 4×4；均以 alignPointer 起始 | 观察 | E2 各 readElement + readMatrix{Full,Linear,Translation} |
| N33 | **场景装配**：`BuildScene(tree,mesh)` 扁平实例化（Name/Path/Transform/Mesh）；节点名 userName→displayName→name 回退 | 观察（设计） | go-nwd `nwd/scene.go` |
| N34 | NWD 的 Blowfish 封存（TOC 校验 M2 + 几何块 M4）由 `internal/blowfish` 自包含实现（标准算法 + pi 初值表），经标准测试向量与既有端到端往返验证字节兼容；不引入 `x/crypto/blowfish`（已弃用告警） | 观察（实现决策） | `internal/blowfish`；N6/N16/N23 |

## C7 轮（2026-10-13，真实样本字节级校正 — BCCCH BIM 25.7MB）

> 样本：`nwd/testdata/BCCCH_BIM Coordination Model_251024.nwd`（Navisworks 2024 发布）。
> 本节修正 M1/M2 的若干静态推断，以真实文件为准。

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N35（修正 N5）** | 页脚 Int64（fileSize−0x3c）是**尾块绝对偏移 N**（非尺寸）；尾块 = `[N, fileSize−0x44)`；其后 `[−0x44,−0x3c)` 8B 间隙、`[−0x3c,−0x34)` Int64 N、`[−0x34,EOF)` 52B 头副本。实测 N=0x187c383 | 观察 | 样本偏移；Load 中 seek 目标实为 `Splitter+0x20`（=N） |
| **N36（修正 N7/N16）** | TOC 每流记录 = `[u32 nameLen][name][u32 bitfield][align8][i64 offset][i64 size][i32 prefix][i32 suffix]`——**无存档 name-adler**；**无尾部 Blowfish 校验**（zlib 流填满尾块，python zlib 全消费 581B）；流名可带 `cache\` 前缀（27 流中 24 条）；`offset/size` 单调衔接，语义确认 | 观察 | 样本尾块 inflate；`analysis/07-real-sample.md` |
| **N37（修正 N21）** | `readString<0>` = `i32 字节长` + UTF-8 字节 + **补齐到 4（填充在数据之后）**；实测 39 字节名在偏移16→结束55→补到56 | 观察 | 样本 Partition 流内偏移 |
| **N38（部分解 U10）** | 尾块签名行实为 **navisworks 变体**：`#LcUStream-V1.1 binary double release utf8 navisworks:451 lizlib\n`；⇒ **NwFormatVersionEx = 451**（对应共享对象门控 0x1C3）。头/页脚签名无版本数字（`...lichunk-` + 3 位数字 + `\n`，此处 `008`） | 观察 | 样本 0x187c383 与 0x0/页脚 |
| **N39** | 主负载各流：实测 **26/27 为 zlib**（魔数 `78 9c`），仅 `GeometryCompress` 非 zlib（Blowfish 几何块容器，0x03000000 位域）。bitfield 非简单压缩位（取值 0x1/0x100/0x10000/0x1000000/0x3000000，字节对齐标记）；**判定以魔数为准** | 观察 | 样本各流首字节 |
| **N40** | Partition 流 inflate 后 = 对象信封：`marker=100`、`typeID=32`(PartitionNode)、`u32 modelType`、ModelBase[`userName`="BCCCH_BIM …nwd"、`→Name(52)` "LcOpPartition"]、`u32 flags`、`u32 guid`、`u32 attrCount`、attrs… ⇒ **M3 信封与 ModelBase/ModelItem 结构在真实文件上得到验证** | 观察 | 样本 Partition 流（744B） |
| N41 | 真实 Partition 根的 attrCount=1，属性为 **PublishAttribute(92)**（payload=flags+6 字符串+2 时间+…）；其后续属性/子节点解码为下一步 | 观察（部分） | 样本；E2 PublishAttributeReader@0xc58ffa |
| **N42** | 真实 Partition 根解码成功：`userName="BCCCH_BIM Coordination Model_251024.nwd"`、`className="LcOaPartition"`、`displayName="File"`、`modelType=0`、`flags=0`、`guidIndex=0`、`attrCount=1`、首属性 typeID=**92**（PublishAttribute）。根头字段序（marker/typeID/modelType/ModelBase[userName,Name]/flags/guid/attrCount）**与 M3 推断一致** | 观察 | 样本 Partition 744B；`File.DecodePartitionRoot` |
| N43 | **PublishAttribute(92) payload 实测 72B**（112→184）：首 i32=`0xffffffff`，随后含 i64 时间戳 `0x69043fda`（Unix 2025‑10‑24，与文件名日期吻合）；字段序与 E2 reader（flags+4串+align8+2时间+4串+explicitName）**未对齐**，需按真实字节继续定案 | 观察（部分） | 样本偏移 112–184；U18 |
| **N44** | **对象索引自描述**：`marker = 100 + slot`；据此可在真实流中顺序定位信封（配合向后重同步）。`ScanNames` 在真实 `PartitionProps`（1.9MB，`PropertyAttribute` 流）上提取 **212 个 Name 对象**（属性键） | 观察 | 样本 PartitionProps；`nwd/attrscan.go` |
| **N45** | 真实属性键例（PartitionProps）：`Location/LcRevitPropertyLocation`、`Latitude/revit_Latitude`、`Longitude`、`Elevation`、`Timezone`、`ProjectLocation`、`Identity/LcOaSceneIdentity`、`Element ID/LcRevitId`、`Category`、`lcldrevit_parameter_Center Radius`… ⇒ 客户端 CDA 属性面可直接枚举 | 观察 | 样本；`File.ScanStreamNames` |
| N46 | 真实流分类：`Partition`=根节点（仅 5 信封：PartitionNode/Name/PublishAttr/DistantLight×2）；`PartitionProps`=PropertyAttribute 对象流；`SpatialHierarchy`=紧凑整数对索引（非信封）；`LogicalHierarchy`=整数列表；`Fragments`=计数 49766 + 记录 | 观察 | 样本各流头 |

## C8 轮（2026-10-13，U20 几何 — 真实网格顶点）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N47** | **Geometry 流 = 64KB zlib 分块串联**：TOC `prefix=4` 起始 4 字节 `00 00 01 00`=0x10000=分块解压尺寸；其后 595 个连续 zlib 成员，解压共 **38,958,248 字节**（单 zlib reader 只解首块，须分块解码） | 观察 | 样本 Geometry 流；`InflateChunks` |
| **N48** | **几何块结构**（解压后对象信封，每块自 marker=100 起）：`Element(94 TriangleSetElem / 95 LineSetElem / 96 PointSetElem)` → `VertexSet(60)` = `[i32 vertexCount][i32 floatCount=vertexCount*3][f32 x,y,z ×]*`（8 字节对齐）→ `NormalSetShort(100)`/`ColorSet(58)`。实测 **14,331 块 / 1,261,016 顶点**（真实模型点云） | 观察 | 样本 Geometry；`DecodeGeometryVertices` |
| N49 | 三角形/线/点**索引**为量化集（NormalSetShort 计数带符号位 0xfffffd51、位打包），未解码 → U21；当前提取顶点坐标 | 观察（部分） | 样本块尾 |

## C9 轮（2026-10-13，U21 几何索引 — 结构定案）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N50** | 三角形元素 = **GeometryShell**：`OdNwGraphicTriangleSetElementReader::readElement` 建壳并调用 `setIndexes(OdArray<u16>)` + `setVerticesCountPerFace(OdArray<u16>)`；4 个嵌套 readObject（Vertex/Normal/TexCoord/Color），随后 `readIndexesPerLine` | 观察 | E2 @0xc2c1ea |
| **N51** | **索引编码** `readIndexesPerLine`：`i32 count` + `count×u16`（未压缩）；压缩时 `readUInt32` + `readIndexTable(OdArray<u32>)` 映射；`alignPointer<0>`(4B) 收尾。线集用 `readVertexesPerLine`（同构，另含 per-line 长度）| 观察 | E2 readIndexesPerLine@0xc2c918、readVertexesPerLine@0xc2ecd4 |
| N52 | 实测本样本元素为**表压缩索引**（NormalSetShort 计数带符号位；块尾无原始 u16 数组），故三角面尚未连接（U21 收口需 `readIndexTable` 语义） | 观察（部分） | 样本 Geometry；`nwdinfo` geometry 摘要 |
| **N53** | `readIndexTable` = **2-bit 标签变长字节流**：每字节 `& 0xC0` 分派（0x00/0x40/0x80/0xC0 四态），低 6 位为值位；即量化/位打包索引。完整状态机待展开（U21） | 观察 | E2 readIndexTable@0xc275de |
| N54 | 几何点云可导出：`cmd/nwdgeom` → PLY（1,261,016 顶点，35MB，格式头合法） | 观察（实现） | go-nwd `cmd/nwdgeom` |

## C10 轮（2026-10-13，U18/U19/U21 真实收口）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N55** | **空字符串**：`readString` 长度为负（-1）表示 null/未设置，仅消费 4 字节长度字段；据此 PublishAttribute payload 精确对齐 72B | 观察 | 样本 Partition 偏移 112 |
| **N56** | **属性布局定案**：属性对象 = ModelBase（userName 字符串 + Name 对象） + `u32 attrFlags`，随后子类字段；`PublishAttribute(92)` = `i32 publishFlags + 4 串(title/subject/author/publisher) + align8 + 2×i64(publishDate/expiryDate) + 4 串(copyright/publishedFor/comments/keywords) + 串(explicitName)`。**真实解码**：user=null、publishFlags=96、publishDate=1761886170（2025‑10‑31 UTC） | 观察 | 样本 Partition；`ObjectReader.decodePublishAttribute` |
| **N57** | **PartitionNode 无内联子节点/usage**：真实流中根节点 = `u32 modelType` + ModelItem（base+flags+guid+attrCount+attrs），其后直接是同级对象（DistantLight×2）。M3 的 `childCount/children/usage` 属夹具推测，已按真实校正；ModelItem 布局在 v451 与推测窗口一致（>248 门控不影响该三字段） | 观察 | 样本 Partition；`decodePartitionNode` |
| **N58** | **几何索引 codec 定案**：`readIndexTable` = 2-bit 标签变长字节流（0x00 递增游程 / 0x40 回指 / 0x80 重复末值 / 0xD0 4bit 字面 / 0xE0 12bit / 0xF0 28bit）；`DecodeIndexTable` 落地并合成测试通过；元素内索引区定位（嵌套 Normal/Color 集尺寸）仍待（U21 尾项） | 观察 | E2 @0xc275de；`DecodeIndexTable` |
| N59 | **真实对象流容错解码**：`DecodeObjectStream` 顺序解码顶层信封与属性，遇未支持类型（如 DistantLight 27）记录并停止；真实 Partition 得 root+PublishAttribute | 观察 | 样本；`nwdinfo.partition_objects` |

**样本校正实现状态**：容器层（M1/M2）在真实 25.7MB 文件上**全量通过**（27 流清单、偏移/尺寸、26 流 zlib inflate）；golden 测试见 `nwd/real_test.go`。

## 挂账（未知 → 队列）

| ID | 问题 | 优先级 | 阻塞 | 状态 |
|---|---|---|---|---|
| ~~U1~~ | ~~TOC rdInt64×2/rdInt32 的 offset/size/chunkCount 对应关系~~ | P0 | M1 收口 | ✅ N15 定案（offset/size/prefix/suffix） |
| ~~U2~~ | ~~主负载 chunk 头格式与 MultiChunk 分块策略~~ | P0 | M2 | ✅ 单块模型定案（N15/N17）；MultiChunk 内部再分块→U7 |
| U3 | 8B 间隙（P+N 处）语义 | P1 | 夹具精确性 | 开 |
| U4 | ascii 模式尾块是否同样携带 lcodapi/lizlib 词 | P1 | 夹具对齐 | 开 |
| U5 | v2–7 LoadOld 布局 | P2 | 按需 | 开 |
| U6 | NwAdler32 校验范围 → 已定案为 N16；新问题：prefix==4 的 chunk0 特殊路径 | P2 | 健壮性 | 部分收口 |
| U7 | MultiChunk 内部负载级 chunk 表 | P2 | M4 按需 | 开 |
| U8 | 未压缩流中段内部帧格式 | P2 | M3 按需 | 开 |
| U9 | Partition/Hierarchy/GeometryCompress/Schemas 流内布局 | P0(P1 清单) | M3–M5 | 🔶 信封+树节点 schema 落地（N19–N22）；Geometry/Schemas 流内格式仍开 |
| U10 | FormatVersionEx 全档位与各门控字段精确布局（>21/>214/>248/>451 分支）；版本注入点（FileInfo vs 流头） | P0 | M3 收口 | 开（夹具固定 fv=100 窗口） |
| U11 | StaticTreeGroup/Leaf（空间层次）与 Fragment 引用编码 | P1 | M4 联调 | 开 |
| U12 | 位打包量化几何（readIndexes/readBits/readIndexTable + 精度还原） | P0 | M4 收口 | 开（需真实样例） |
| U13 | GeometryCompress 块计数/每块精确布局 + 块↔几何索引映射 | P1 | M4 收口 | 开 |
| U14 | Fragment 11 flag 位 × 8 版本门控精确字段序 | P1 | M4/M5 联调 | 开 |
| U15 | CommonSchemas 流顶层计数/字段序与真实流名 | P0 | M5 收口 | 开（夹具对齐布局） |
| U16 | PropertyAttribute 嵌套值编码 + PartitionProps 块↔节点映射 | P1 | M5 收口 | 开 |
| U17 | ObjMatrix(17) 元素数（12/16）与排列 | P2 | M6 收口 | 开 |
| U18 | 真实属性类型 payload 全表 | P0 | M3/M5 收口 | ✅ PublishAttribute 定案（N56）；余 70/76/79/86/88/180 同基类 |
| U19 | 完整模型树（SpatialHierarchy 索引 → 节点层级） | P1 | M3 收口 | 🔶 结构观察（N62：[count,index] 记录引 Partition item）；完整文法待 |
| U20 | GeometryCompress 设置来源 | P1 | M4 收口 | 🔶 GenSubkeys2=标准 Blowfish（N64）；40B 非设置明文，来源待 |
| U21 | 几何三角索引：codec 已定（N58 `DecodeIndexTable`）；**元素内索引区定位**（嵌套集尺寸 + 压缩标志）待 | P1 | M4 收口 | 🔶 codec 落地（N58/N61） |
| U22 | GeometryCompress 流实为 40B（本样本）之语义（是否空/占位） | P2 | M4 | 开 |

## C11 轮（2026-10-13，残余任务结构定案）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N60** | `NormalSetShort(100)` = `[i32 -count][i32 flags][count × i8]`（量化法线，1 字节/法线；实测 count=-687，686 字节 0xd4 游程） | 观察 | 样本 Geometry 块 8272..8976 |
| **N61** | `TriangleSetElement(94)` read 顺序：`4×readObject`（Vertex/Normal/TexCoord/Color 集，缺失为 nil 标记）→ `readVertexesPerLine(u16 每面顶点数)` → `readIndexesPerLine(u16 索引，表压缩)` → `validateIndices`。索引区定位依赖 GeometryCompressSettings 的压缩标志（U20）+ 各嵌套集精确尺寸 | 观察 | E2 TriangleSetElementReader@0xc2c1ea |
| **N62** | `SpatialHierarchy`（484KB）= 头部小整数（5/7/5/4…）+ `[u32 count][u32 index]` 记录（如 `1,24113`），引用 Partition 树的 item（`SpatialHierarchyStreamLoader::parseStream` → `PartitionStreamLoader::getTreeItem`）；完整层级待展开（U11/U19 尾） | 观察 | 样本 SpatialHierarchy 头；E2 @0xcff23c |
| **N63** | GeometryCompress 使用 **`NwBlowfish::GenSubkeys2`（非标准密钥编排：按键字节求和填充）**，非标准 Blowfish；故 40B 设置流的标准 Blowfish 解密失败 → 几何压缩设置（坐标/颜色精度、indices/lengths 压缩位）仍待（U20/U22） | 观察 | E2 GenSubkeys2@0xbcdddc |

**残余任务结论**：U21 元素内索引区定位、U19 Spatial 完整层级、U20 几何压缩设置三项均需进一步深度逆向（GenSubkeys2 状态机、嵌套集尺寸解析、Spatial 记录文法），收敛不确定；现有交付（容器/流/根/属性/顶点/索引 codec）已覆盖真实文件的主要可读信息。

## C12 轮（2026-10-13，U20/U21 收口尝试）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N64** | `NwBlowfish::GenSubkeys2` = **标准 Blowfish 密钥编排**（相位1：key 字节循环（`divl keylen`）组装 32 位字 XOR 进 18 个 P；相位2：`BF_En` 迭代填充 P/S）。⇒ 与 GenSubkeys 同义，故 40B GeometryCompress 的**标准解密结果即真实明文** `81 70 ae 6b …`（高熵），**并非明文设置结构** → 该 40B 或为摘要/占位，几何压缩设置来源另寻 | 观察 | E2 GenSubkeys2@0xbcdddc |
| **N65** | 元素索引/每面顶点数数组**非简单原始 u16**：对真实块0（0..9640）按 `[i32 count][count×u16]` 精确落位搜索失败 ⇒ 走**表压缩路径**（`readIndexTable` 等，N58）；数组定位需 `readVertexesPerLine/readIndexesPerLine` 头部字段 + 压缩标志 | 观察（部分） | 样本 Geometry 块0 |

**取舍**：U20/U21 尾项依赖「几何压缩设置来源」与「元素数组头部文法」，二者互为前置且未收敛；不交付推测解码器。
