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
| U3 | 8B 间隙（P+N 处）语义 | P1 | 夹具精确性 | 开（不影响真实文件解析；E2 Load@0xbd37e7 seek 序列可进一步反汇编定案，纯夹具对齐问题） |
| U4 | ascii 模式尾块是否同样携带 lcodapi/lizlib 词 | P1 | 夹具对齐 | 开（**需样本**：无 ascii 模式样本；真实样本均为 binary） |
| U5 | v2–7 LoadOld 布局 | P2 | 按需 | 开（**需样本**：2013–2016 旧版文件；E2 存在 LoadOld 入口，现代 v8 全链路不受影响） |
| U6 | NwAdler32 校验范围 → 已定案为 N16；新问题：prefix==4 的 chunk0 特殊路径 | P2 | 健壮性 | 部分收口 |
| U7 | MultiChunk 内部负载级 chunk 表 | P2 | M4 按需 | 开（**需样本**：两真实样本均为单块模型；MultiChunk 路径未触发） |
| U8 | 未压缩流中段内部帧格式 | P2 | M3 按需 | 开（按需；真实属性流已按对象信封解码） |
| U9 | Partition/Hierarchy/GeometryCompress/Schemas 流内布局 | P0(P1 清单) | M3–M5 | 🔶 信封+树节点 schema 落地（N19–N22）；Geometry/Schemas 流内格式仍开 |
| U10 | FormatVersionEx 全档位与各门控字段精确布局（>21/>214/>248/>451 分支）；版本注入点（FileInfo vs 流头） | P0 | M3 收口 | 🔶 大幅收敛（N122）：FormatVersionEx=尾块 navisworks:<N>（431/451 实测解析）；主要门控（materialJson>446、共享节点≥451、explicitName 关闭）已按真实版本落地；仅旧档位（≤202/≤248/≤30）分支需旧样本 |
| U11 | StaticTreeGroup/Leaf（空间层次）与 Fragment 引用编码 | P1 | M4 联调 | 🔶 N120/N123：SpatialHierarchy 流=fragment 索引；StaticTree(1/2) 不在两真实样本的 LogicalHierarchy 对象流中出现（walk gap 簇中为 resync 误读）；readTreeItem 文法已反汇编（readObject + NwTreeItemType 枚举 ≤5 + u32 fragment 回调）待真实样本启用 |
| U12 | 位打包量化几何（readIndexes/readBits/readIndexTable + 精度还原） | P0 | M4 收口 | 开（**需样本**：文法已定 N73，两真实样本均不触发该路径，实现不可证伪） |
| U13 | GeometryCompress 块计数/每块精确布局 + 块↔几何索引映射 | P1 | M4 收口 | 开（**需样本**：本样本该流仅 40B 占位；几何走 Geometry 流，主线不受影响） |
| U14 | Fragment 11 flag 位 × 8 版本门控精确字段序 | P1 | M4/M5 联调 | 🔶 逐记录遍历已用信封重同步交付（N101/N104：47,016 条、映射 100% 吻合）；完整逐字段文法需更多版本样本 |
| U15 | CommonSchemas 流顶层计数/字段序与真实流名 | P0 | M5 收口 | 开（**需样本**：BCCCH 的 LcOpCommonSchemas 仅 11 字节近空，无真实内容可验证；夹具端到端绿） |
| U16 | PropertyAttribute 嵌套值编码 + PartitionProps 块↔节点映射 | P1 | M5 收口 | ✅ N118 readData 定案 + N121 块表；块值↔树项最终对应待验（N121） |
| U17 | ObjMatrix(17) 元素数（12/16）与排列 | P2 | M6 收口 | 开（E2 可推进：ObjMatrixReader readElement 待反汇编定元素数；两真实样本 fragment 变换以 14/15/16 为主，17 未触发——**需样本**验证） |
| U18 | 真实属性类型 payload 全表 | P0 | M3/M5 收口 | ✅ PublishAttribute 定案（N56）；余 70/76/79/86/88/180 同基类 |
| U19 | 完整模型树（SpatialHierarchy 索引 → 节点层级） | P1 | M3 收口 | ✅ N117/N119/N122：DecodeLogicalHierarchy 深度遍历（460 对象/树深 7，Model Lines 等类目子树完整）；两簇 exotic 节点 gap 已记录（N122） |
| U20 | GeometryCompress 设置来源 | P1 | M4 收口 | 开（**需样本**：40B 解密为高熵非明文（N64），疑占位/摘要；几何顶点已不依赖它（N71）） |
| U21 | 几何三角索引：codec 已定（N58）；元素内索引区**无法精确落位**（N66 块0 零候选） | P1 | M4 收口 | 🔶 codec 落地；组合未收敛 |
| U22 | GeometryCompress 流实为 40B（本样本）之语义（是否空/占位） | P2 | M4 | 开（**需样本**：同 U20；不影响 Geometry 流主线） |

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

## C13 轮（2026-10-13，U21 收口尝试 + topo 对接）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N66** | **元素索引区在真实块上无法精确落位**：对真实块0（0..9640，vc=687）以 `readIndexTable` codec 做「精确落在块尾」搜索得 **0 个候选**；宽松容差（landing ≤7B）得 7731/24765 但疑为巧合。⇒ 元素组合（4×readObject 的嵌套集尺寸 + `readVertexesPerLine/readIndexesPerLine` 头部文法，且依赖不可恢复的 GeometryCompressSettings）**仍未收敛** | 观察（部分） | 样本 Geometry；U21 |
| **N67** | **go-topo 对接落地**：新增 `go-topo/nwd.go`（NwdReader/NwdElement）——LineSet(95)→边复合 Shape（精确）；TriangleSet(94)→顶点+BBox（三角面待 U21，`SetTriangleSoup` 尽力而为）；`cmd/nwd2mesh` 导出 STEP（5.9MB/83954 实体）与二进制 STL（三角形汤 154292 面/7.4MB）；真实样本测试 `nwd_test.go` 通过 | 观察（实现） | go-topo |

## C14 轮（2026-10-13，第二样本 GateHouse 验证）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N68** | **FormatVersionEx 431 的几何走压缩顶点路径**：GateHouse 首个元素（marker100/type94）的首子对象「VertexSet(60)」字段为 `[92][78]`（`fc≠vc*3`），与 BCCCH(v451) 的 `[vc][3vc]` 原始 f32 路径不同。⇒ 逐元素扫描会产生 15 个**巧合假阳性**（72 顶点）；改为「探测首元素：若 `fc≠vc*3` 即判定全流压缩并整段拒绝」→ GateHouse 0 块，BCCCH 14337 块/1,261,783 顶点（bbox 981×854×39 m，物理合理）。压缩顶点解码仍依赖不可恢复的设置（U20） | 观察（实现） | `nwd/geomreal.go`；样本 GateHouse block0 @0 |
| **N69** | **NWD 可内嵌 SQLite 数据库**：GateHouse 流 `LcOpFileDatabaseElementNWD`（off 558605/size 11678）膨胀后以 `SQLite format 3\0` 起始，含 TimeLiner 表 schema（`TK_Item/TK_Object/TK_Step/TK_Resource/TK_ObjectStep/TK_ItemGroup/...`，本样本 0 行）。⇒ NWD 的 4D/TimeLiner 数据以标准 SQLite 存储；对应流名 `LcTl*`（LcTlTimelinerElement/LcTlSimulateDurationElement/LcTlGUISettingsElement）与 Presenter `LcOw*` 亦为 v431 新增 | 观察 | `LcOpFileDatabaseElementNWD` 头；`real_test.go:TestGateHouseEmbeddedSQLite` |
| **N70** | **流命名空间与分区头随版本/来源变化**：GateHouse 流名前缀为 `gatehouse.nwd\`（非 `cache\`），并含独立流 `nwd:stretchr.lwi`（内嵌 LWI）。分区根 `LcOpNwdPartition`（user=`gatehouse.nwd`/class=`LcOaPartition`/display=`File`）**带 3 个 PublishAttribute**（BCCCH v451 仅 1）。⇒ 容器/流/根解析对命名空间与属性数量不敏感，跨版本成立 | 观察 | `real_test.go:TestGateHousePartitionRoot` |

**第二样本验证结论**：容器（37 流/ver8/double/release）、流膨胀、分区根、嵌入 SQLite 在 v431 上**全部通过**；几何因压缩顶点路径（N68）安全拒绝（0 块，不产错误几何）。gatehouse golden 测试已加入 `nwd/real_test.go`（缺样本自动跳过）。

## C15 轮（2026-10-13，U20/U21 收敛：压缩顶点 = 共享位置池 + 索引表）

从 `TNW_Db.tx` 反汇编还原了顶点与索引的真实读取路径（`findings N71`）：

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N71** | **VertexSet 的“压缩顶点”并非加密设置，而是共享位置池 + 索引表**。`readElement@0xc26590`：`compressed ? readVertices : readInt32+3×f32`。`readVertices@0xc26e80`：`count=readInt32`；若 `count>0` 调 `readIndexes(buf, a=3, b=count, c=1, ...)`；`readIndexes` 的 `c==1` 分支读 `n=readUInt32` 个 f32 进 `flt`，置 `*ret=n/a`；随后（共享尾）若 `b > *ret` 调 `readIndexTable(buf, idx, b)`，否则 `idx=[0..b-1]` 恒等。最后 `fillPoint3dArrayByIndexes(count, idx, flt)`：`out[i]=(flt[3·idx[i]], +1, +2)`。⇒ **统一布局**：`[i32 vertexCount][i32 floatCount][floatCount×f32][当 floatCount/3 < vertexCount 时: 索引表]`。所谓 v451 “未压缩”= `floatCount==3·vertexCount`（恒等索引）；v431 “压缩”= 位置池去重 + 索引表。**U20 的 40B 设置流与几何压缩无关**；**U21 的“索引区”即此 `readIndexTable`** | 观察 | E2 readElement@0xc26590 / readVertices@0xc26e80 / readIndexes@0xc267c2 / fillPoint3dArrayByIndexes@0xc26a49 |
| **N72** | **`readIndexTable@0xc275de` 精确文法**（2-bit 标签）：`0x00`=连续递增 run(长度 b&0x3F+1)；`0x40`=回抄 `out[len-(b&0x3F)]`；`0x80`=重复末值 (b&0x3F+1) 次；`0xD0`=字面量 `~(b&0x0F)`；`0xE0`=回抄 `out[len-((b&0x0F)<<8|next)]`；`0xF0`=16 位字面量（2 字节大端）；`0xF1`=32 位字面量（4 字节大端）；结束 `alignPointer<0>`。旧实现的 `0xD0/0xE0/0xF0` 语义有误，已按反汇编修正 | 观察 | E2 readIndexTable@0xc275de |
| **N73** | **`readBits@0xc2737a`（量化路径，`count<0` 时）**：`sum=Σflags[i]`；读 `ceil(sum·cntB/32)` 个 i32，每字 32 位 **高位优先** 拆为 bit 流；按 `cntB` 行、每行 4 个分量，`flags[c]>0` 时读 `flags[c]` 位组成值；不足 `cntB·a` 补 0。配合 `readVertices` 负 count 分支：`count=-count; scale=readFloat; bbox[6]=6×f32; readIndexes(3,count,3,...)`，再按 `flags` 逐轴反量化 `init[i]`（0→0；1→span；≥2→span/sign(scale)）后 `fillPoint3dByInitFloats` | 观察 | E2 readBits@0xc2737a |

**结果**：BCCCH 几何 14337→**16097 块 / 1,354,667 顶点**（新增 1760 个去重块）；GateHouse 几何由 0 → **32 块 / 963 顶点，bbox ≈ 11×7.6×3.4 m（物理合理）**。两个真实样本现均可完整解出顶点/索引；量化（负 count）路径按 N73 实现（样本未触发，留待验证）。

## C16 轮（2026-10-13，三角面（Element）文法还原）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N74** | **三角元素（`TriangleSetElement` type94）读取顺序**：`readElement@0xc2c1ea` 依次 `readObject` 读 4 个子对象——VertexSet(60)、TexCoordSet(61)、NormalSet(`type 0`)、ColorSet(58)（缺失者不写）——`setVerticesData`；随后 `readVertexesPerLine`（每面顶点数）→ `setVerticesCountPerFace`；**再 align4**；若 `fmtVer>0x13(19)` 则 `readIndexesPerLine`（扁平索引）→ `setIndexes`。最后 `validateIndices/Normals/Colors/TexCoords`。面 = 按 `vertexesPerLine` 切分 `indexesPerLine` | 观察 | E2 TriangleSetElementReader::readElement@0xc2c1ea |
| **N75** | **`readVertexesPerLine@0xc2ecd4` / `readIndexesPerLine@0xc2c918` 文法**。未压缩：`[u32 n]` + n 值（`fmtVer>0x4a(74)` 为 u16，否则 u32 低 16 位）+ align。压缩（vpl）：`[u32 total][align][i32 bits][i32 unique][readBits 位流][当 unique<total: 索引表]`；压缩（ipl）：`[i32 n][索引表 n 项]`。⇒ 面连通性可用 `readBits`+`readIndexTable` 解出 | 观察 | E2 readVertexesPerLine@0xc2ecd4 / readIndexesPerLine@0xc2c918 |
| **N76** | **子对象亦走压缩变体**：`NormalSetShort(100)=[i32 -count][i32 flags][count×i8]`（BCCCH 元素0 实测 687 字节 0xd4）；`NormalSetFloat`/`ColorSet`/`TexCoordSet` 各有 `getGeometry*Compressed`+`get*PrecisionReducedFlags` 门控的压缩/未压缩读取器。⇒ 完整元素遍历需先解析这些子对象（依赖不可读的 GeometryCompress 40B 所承载的压缩标志，或逐类型试解析） | 观察（部分） | E2 NormalSetShortReader::readElement@0xc21e74 等 |

**现状**：几何**顶点**（含 v451 恒等/v431 去重池）两样本均完整解出并落地（N71）；**面连通性**文法已还原为可测试原语 `ReadBits/ReadVertexesPerLine/ReadIndexesPerLine/SplitFaces`（`nwd/faces.go`，单测通过），待补子对象遍历后即可产出真实三角面（下一步）。

## C17 轮（2026-10-13，元素面数组实测与索引空间）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N77** | **BCCCH 元素0 面数组实测**：`NormalSetShort` 之后为**压缩 vpl**：`[u32 total=145][i32 bits=6][i32 unique=145]`（@8980）+ 28 个字位流；`align` 后**压缩 ipl**：`[i32 n=977][索引表]`（@9104），解出 977 项、恰好在元素边界（≈9640）结束。`Σ(vpl)=977=len(ipl)` —— 佐证 vpl+ipl 解码正确 | 观察 | 样本 Geometry 元素0（0..9640） |
| **N78** | **`validateIndices@0x10de390` 只做顶点数组扩容**：遍历索引求 `maxIdx`，然后 `vertices.resize(maxIdx+1)`（不做索引变换/相对化）。⇒ 元素索引空间**可超出该元素 VertexSet 的顶点数**（元素0：顶点687，索引max 973）→ 顶点为**跨元素共享/累积缓冲**（fragments/shared-nodes 层），面组装的索引空间基准仍待定（U23） | 观察 | E2 OdNwVerticesDataImpl::validateIndices@0x10de390 |

**本轮小结**：元素面数组（vpl/ipl）解码已验证自洽（`Σvpl==ipl`），并新增可测试原语 `ReadBits/ReadVertexesPerLine/ReadIndexesPerLine/SplitFaces`。剩余：子对象（TexCoord/Normal/Color）遍历 + 索引空间的共享顶点基准（U23）。

## C18 轮（2026-10-13，面组装落地：累积顶点池 + 相对索引）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N79** | **索引空间 = 累积顶点池 + 元素相对偏移**。几何流所有元素 VertexSet 依序拼成一个顶点池 `pool`；元素 i 的基准 `base_i = Σ_{j<i} vc_j`；其 `indexesPerLine` 值为**相对 `base_i`** 的偏移。实测：相对模型平均边长 4.14 vs 绝对模型 49.99（模型跨度≈980）⇒ 相对模型成立。`validateIndices` 只 `resize(maxIdx+1)`（N78）与此一致（池按需增长） | 观察（度量） | 样本 Geometry；elem0 idx≤973 > 自身687 |
| **N80** | **面数组定位器（确定性验证）**：元素内自 `vsEnd` 起，取首个满足 «压缩 vpl = `[u32 total]`+align4+`[i32 bits][i32 unique]`+位流（alignPointer<0>=**4** 字节，非 8）+ 可选索引表» 且其后 «压缩 ipl = `[i32 n]`+索引表» **恰好终止于元素边界** 且 `Σ(vpl)==len(ipl)` 的候选。BCCCH 命中 7649/16097 个带顶点元素、324108 面、1,806,959 三角（退化 0.47%）；其中 36% 面为 3/4 边形，余为大多边形（shell/strip） | 观察（实现） | `nwd/elements.go`；对齐实测 align4 |

**交付**：`nwd/elements.go`（`DecodeElements`：顶点 + 经验证的 vpl/ipl）、`nwd/mesh.go`（`DecodeMesh`：累积池 + 相对索引 + 扇形三角化）。BCCCH 产出 1.8M 三角、物理 bbox；GateHouse（v431）面数组定位未命中（其子对象布局不同，待续）。单测 `TestRealMesh` 通过。

## C19 轮（2026-10-13，定位修正：NWD 为网格格式，改为直出 MST/glTF）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N81** | **NWD 几何是"显示/缓存网格"，非 BREP**：BimNv 几何类仅 `OdNwGeometryShell`（`getVerticesPerFace/getIndices/getTriangles`）、`LineSet`、`PointSet`（+少量 `Circle`/`Cylinder` 解析基元仅用于派生/标注）。无 BREP 拓扑（面-环-边-曲面/NURBS/ACIS）。⇒ 与 DGN/RVT/IFC 的**精确 BREP** 不同；NWD 由 Navisworks 对源模型**三角/面片化缓存**而来，精确几何被丢弃 | 观察 | BimNv 头文件；本仓几何解码 |
| **N82** | **架构调整**：因 NWD 为网格，**移除 go-topo 的 NWD 接入**（`nwd.go`/`nwd_test.go`/`cmd/nwd2mesh` + go.mod 依赖），改采 **go-rvm 式直出**——`go-nwd/export`（`WriteMST`/`WriteGLTF`）+ `cmd/nwdexport`（`--format=mst|gltf|both`，`--gltf-format=glb|gltf`）。NWD→STEP 之类 BREP 转换（必有损）不再作为主线 | 观察（实现） | `export/export.go`；go-topo 移除 |

**交付**：`go-nwd/export`（MST：单实例/单节点/三角面 + 平滑法线；glTF：POSITION/NORMAL/索引 + PBR 材质，.glb/.gltf）、`cmd/nwdexport`。BCCCH 直出 1.35M 顶点/1.81M 三角（.mst/.glb ≈54MB）；GateHouse 963 顶点。往返单测通过（`mst.MeshReadFrom` / `gltf.Open`）。

## C20 轮（2026-10-13，解析基元三角化）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N83** | **解析基元的序列化与三角化（对齐 go-rvm 的基元处理）**。元素类型：`CircleElement=104`、`CylinderElement=105`（`TextElement=103` 未做，需字体）。布局（`readElement`）：Circle=`[i32 flags][f32×3 origin][f32×3 xVector][f32×3 yVector][f32 radius]`；Cylinder=`[i32 flags][f32×3 bottom][f32×3 top][f32×3 xAxis][f32×3 yAxis][f32 radius]`。SDK `toShell(pointPowerOfTwo=4)`→16 段：Circle 为**圆盘扇形**（EllipArc3d 的 major=minor=radius，即半径 r 的圆）；Cylinder 为**侧壁 + 双端盖**。go-nwd 按此实现（`nwd/primitives.go`），产出顶点 + 三角（identity 索引），经 `DecodeMesh` 进入 MST/glTF | 观察 | E2 Circle/CylinderElementReader::readElement@0xc32d82/0xc33eb2；toShell@0x10ef76c/0x10f284c |
| **N84** | **两个真实样本均无解析基元**：元素类型直方图仅 94/95（TriangleSet/LineSet），无 103/104/105。⇒ 基元路径以合成单测验证（圆环半径/平面、圆柱顶点数/三角数、端到端 `DecodeMesh`）；样本导出不受影响（三角数不变 1,806,959）。同时导出器补齐 **LineSet→边**（MST `EdgeGroup`、glTF `PrimitiveLines`） | 观察 | 样本类型直方图；`primitives_test.go` |

**交付**：`nwd/primitives.go`（`decodeCircleElement`/`decodeCylinderElement`/`circleRing` + 16 段三角化）、`elements.go`/`mesh.go` 接入 104/105、`export` 支持边。单测通过。

## C21 轮（2026-10-13，面语义定案：shell 面 = 三角形带，非扇形）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N85** | **`OdNwGeometryShellImpl::createTriangleFaces@0x10e1776`：shell 的每个面按“三角形带（strip）滚动窗口”展开，而非扇形（fan）**。字段：`+0x58`=verticesPerLine（`setVerticesCountPerFace` 写入）、`+0x60`=indexesPerLine（`setIndexes` 写入）。算法：设面顶点 `p[0..n-1]`（`n<3` 跳过），对 `k=0..n-3` 发射三角 `T_k`；用三槽 `(s0,s1,s2)` 滚动：偶数 `k` → `(p[k],p[k+1],p[k+2])`，奇数 `k` → `(p[k+1],p[k],p[k+2])`（即每步将新顶点写入交替槽位，等价 GL 三角带展开，相邻三角绕序相反）。四边形 = `(p0,p1,p2),(p2,p1,p3)`；五边形 = `(p0,p1,p2),(p2,p1,p3),(p2,p3,p4)`。相邻两条面/带边共享，非扇形共用 p0 | 观察 | E2 createTriangleFaces@0x10e1776（槽写入 `movw %dx,-0x32(%rbp,%rax,2)`，`rax=ee` 0/1 交替）；getTriangles@0x10e16f0 经 `std::function` 语法调用；draw lambda@0x10e0a08 逐三角 push 3 索引 + `odgiFaceNormal(...,3,...)` 佐证输出为三角 |
| **N86** | **扇→带修正已落地**：`nwd/faces.go` 新增 `StripTriangles`（可单测），`nwd/mesh.go` 的 94/104/105 分支改用它。两者每面三角数同为 `n-2`，故三角总数不变（BCCCH 1,806,959），仅四边形/多边形的对角线选择与绕序由“扇形”改为“带”（对齐 SDK）。`faces_test.go:TestStripTriangles`、`real_test.go:TestRealMesh` 通过 | 观察（实现） | `nwd/faces.go`/`nwd/mesh.go` |

**说明**：C19 曾以“扇形三角化”直出；N85 表明 SDK 权威展开是三角带，四边形以上面的对角线选择与绕序均不同（凸平面场景覆盖面积相同，非平面则不同）。此项关闭复盘中“大多边形语义未证实（polygon/strip/fan、绕序）”的疑问。

## C22 轮（2026-10-13，战役 A：元素子对象文法 + 确定性遍历；“47%/GateHouse 0”归因）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N87** | **元素子对象为“按位次的 4 个信封”**：`TriangleSetElementReader::readElement@0xc2c1ea` 依次 `readObject` 期望类型 60 VertexSet / 61 TexCoordSet / 0 NormalSet / 58 ColorSet；**缺失者写为 marker=0 的空信封（4 字节）**。之后 `readVertexesPerLine` → **align4** → `readIndexesPerLine`。压缩标志来自 `OdNwGeometryCompressSettings`（`getGeometry{Lengths,Indices,Color,Normal,TexCoord}Compressed` 与 `get*PrecisionReducedFlags`），即 U20 的设置流 | 观察 | E2 readElement@0xc2c1ea；各子 reader |
| **N88** | **子对象负载文法**（反汇编）：VertexSet(60)=`[i32 vc][i32 fc][fc×f32]`（`fc<3·vc` 时随索引表，N71）；TexCoordSet(61)=`[i32 n][n×(f32,f32)]`（@0xc29ad0，压缩变体存在）；NormalSetFloat(59)=`[i32 n][n×(f32,f32,f32)]`（@0xc22926）；ColorSet(58) 未压缩=`[i32 a][i32 n][n×u32]`+align4（@0xc201b4，压缩为位打包+`getGeometryColorCompressed`）；**NormalSetShort(100) 压缩**（@0xc222e4）=`[i32 n][i32 unique][readBits(flags=[F,F,F,0], count=unique, stride=3·unique)][unique<n 时 n 项索引表]`，`F`=`getNormalsPrecisionReducedFlags`（0/>15 时默认 16）。**实测 unique=0 合法**（所有法线共享一值，位流为空、索引表承载游程，如 BCCCH 元素0：n=687、unique=0、687 字节 0xd4） | 观察 | E2 各 reader；样本元素0 |
| **N89** | **确定性遍历落地并验证等价**：新增 `nwd/subobjects.go`（`readEnvelope` + `childOptions` 组合式遍历 + 各 `skip*` + `locateFacesDeterministic`），`DecodeElements` 改用它为主、`locateFaceArrays` 兜底。在 BCCCH **全部 14528** 个带 VertexSet 的 type-94 元素上，与旧边界锚定扫描**逐元素面数组完全一致**（`differ=0`，`real_test.go:TestElementWalkDeterministic`）⇒ 旧扫描的“低概率误匹配”风险由此排除 | 观察（实现） | `nwd/subobjects.go`；`nwd/elements.go` |
| **N90** | **“47% / GateHouse 0”归因：非定位器缺陷，而是空面表元素**。BCCCH 带 VertexSet 的 type-94 元素 16097：**有面 7649**、**空面候选 6726**（其元素尾 4 字节=0，即 `[i32 n=0]` 空索引表；尾部实测如 `01 00 00 00 04 00 00 00 01 00 00 00 00 00 00 40 00 00 00 00` ⇒ 单条“0 顶点面”⇒ 不产三角）。**GateHouse v431 的 17 个 type-94 元素全部为空面**（尾 4 字节全 0，结构同上）⇒ **v431“面数组 0 命中”是真实数据无三角面**，非解码失败。两样本的“未解释面”由此基本解释 | 观察（实现） | 样本；`TestElementWalkDeterministic`（face-bearing=7649、emptyFace=6726、agree=14528） |

**战役 A 收口**：子对象文法（N87/N88）与确定性遍历（N89）落地；复盘中“面数组启发式非确定性”“BCCCH 53% 未解释”“GateHouse 0 命中”“低概率误匹配”四项**关闭或归因**。剩余（非子对象问题）：量化顶点路径的真实样本验证、Text/基元、以及**若后续发现空面元素应含面**则需复查（当前证据支持为空面）。

## C23 轮（2026-10-13，战役 D 首项：元素属性存在性与法线解码）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N91** | **两真实样本的元素仅有 NormalSetShort，无颜色/UV 集**。BCCCH 带 VertexSet 的 type-94 元素子对象序列直方图：`[nil·TexCoord, NormalShort(100), nil·Color]` 8470 例；**无任何 ColorSet(58)/TexCoordSet(61)/NormalSetFloat(59)**。GateHouse 同：`[0 100 0]` 15 例。⇒ 复盘“逐元素法线/颜色/UV 缺失 → 材质/颜色丢失”中，**颜色/UV 在这两个样本里本就不存在**（非解码器缺失）；材质/颜色须来自 Material/Fragments 层（战役 C） | 观察 | 样本子对象直方图；`TestElementWalkDeterministic` |
| **N92** | **NormalSetShort(100) 值重建定案**：`getNormalComponentsFromBitsArray@0xc221bd` 仅取 `bitsArray[3·idx..+2]`（3 个连续 u16）；`readNormals@0xc222e4` 将每个分量左移 `(16−F)` 得 16 位有符号值（`movswl`），组向量后归一化；`F`（`getNormalsPrecisionReducedFlags`）由**端锚定遍历**唯一确定（不同 F 改变位流长度从而改变落点）。`unique==0` 时位流为空、全为“空法线”（零向量） | 观察 | E2 @0xc221bd/@0xc222e4；`decodeNormalShort` |
| **N93** | **真实法线落地**：`nwd/subobjects.go:decodeNormalShort` + `locateFacesDeterministic` 带回法线；`ElementGeometry.Normals`。BCCCH 实测 **7649 个元素带法线、共 1,201,569 条、其中 688,526 条非零且均为单位向量**（`TestElementNormals`、`TestDecodeNormalShort`）⇒ 导出可用真实逐顶点法线替代计算平滑法线 | 观察（实现） | `nwd/subobjects.go`/`elements.go` |

**战役 D 状态**：法线 ✅（N92/N93）；颜色/UV 受样本数据限制（N91），非解码缺口；材质需随战役 C（MaterialElement/Fragments）一并解决。

## C24 轮（2026-10-13，战役 D：法线接入导出，端到端）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N94** | **逐顶点法线接入场景网格与导出**：`SceneMesh.Normals`（与顶点池对齐）；`DecodeMesh` 按元素填充；`export.meshNormals` 优先用网格自带法线（空法线以计算平滑法线补全），仅当无法线时才全量计算。glTF NORMAL 访问器由此来自 SDK 解出的真实法线而非计算值。BCCCH 端到端：`nwdexport` 产出 `POSITION`/`NORMAL`（count=1,354,667，bbox 981×854×39 m 不变）；`TestWriteGLTFUsesMeshNormals` 断言导出写回即网格法线 | 观察（实现） | `nwd/mesh.go`/`export/export.go`；`nwd/real_test.go:TestElementNormals` |

**战役 D 收口**：法线（N92/N93/N94）端到端 ✅；颜色/UV 受样本数据限制（N91），非解码缺口；材质归入战役 C。

## C25 轮（2026-10-13，战役 C 起步：Fragments 流结构）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N95** | **`LcOpNwdFragments` = `[u32 count][envelope(≥100, typeID=13 OdNwFragment)…]`**，扁平对象流。实测 BCCCH：**count=49766**，首记录 `marker=100/typeID=13`，其后 `[align8] f64 traversableScale=1.0, u32 traversableTris=4, u32 flags=8, u32 fragmentFlags=256, [align8] readObject(transform 14–17 或 geomref 93), …RunPath/版本门控尾字段`。字段序与 `OdNwFragmentReader::readElement@0xc5cac6`（起始 `alignPointer`→`readDouble`→`readInt32`→`readInt32`→`readInt32`→`readObject`）及 N25 一致；`fragmentFlags` 经多档 fv 掩码（0x6ffd3fff / 0x6ffd3f7f / …）归一 | 观察 | E2 @0xc5cac6；样本流头；`TestFragmentsHeader` |
| **N96** | **Fragments 头解码落地**：`nwd/fragments.go`（`DecodeFragmentsHeader`：count + 首记录 `Scale/Tris/Flags/FragmentFlags`；`StreamFragments` 常量）。BCCCH 实测 `count=49766, Scale=1.0, Tris=4, Flags=8, FragmentFlags=256`（`TestFragmentsHeader`）⇒ 实例化数据入口打开 | 观察（实现） | `nwd/fragments.go` |

**战役 C 状态**：流结构与记录头定案（N95/N96）；Fragment→几何引用（transform/geomref 的 readObject 分支与 RunPath）与**逐记录遍历**、**实例变换落地**、**顶点池基准 U23 确定化**仍待后续轮次。

## C26 轮（2026-10-13，战役 E（参照替代）+ U23 佐证）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N97** | **无参照自洽验证落地**：`nwd/meshstats.go:ValidateMesh` 计算索引覆盖、退化三角、边流形度。BCCCH 实测：顶点 1,354,667 / 三角 1,806,959 / **退化 13,103（0.73%）** / 引用顶点 921,503（68%）/ 边：**内部（恰好 2 面共享）2,008,513、边界 478,858、非流形 242,649** ⇒ **80.7% 的边恰好被 2 个三角共享** | 观察 | `TestMeshValidation` |
| **N98** | **U23 顶点池基准获独立佐证**。若“累积池 + 元素相对索引”错误（如真为按 fragment 的池或绝对索引），跨元素索引将错乱 ⇒ 几何碎片化、退化率极高且几乎无边共享。实测**退化率仅 0.73%、边 2 面共享率 80.7%**，与正确网格一致。⇒ 当前池模型在真实样本上**自洽成立**（非流形 10% 符合显示网格的重叠/重复顶点特征）。外部参照（Navisworks/ODA 运行时）不可得，故以自洽不变量作为独立验证（计划 E2） | 观察（度量） | `TestMeshValidation`；N79 |

**战役 E 状态**：E2（自洽不变量）✅（N97/N98）；E1（ODA/Navisworks 逐元素对拍）受运行环境限制不可得，已用不变式替代并记录。**U23 由“实测假设”升级为“自洽佐证”。**

## C27 轮（2026-10-13，战役 C：Fragment 逐记录遍历 + 实例变换）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N99** | **Fragment 逐记录遍历与实例变换落地**：因记录长度版本门控、未完全走通，改用**信封重同步**（marker≥100 且 typeID=13）并以「traversableScale 合理（0..1e6）」校验，遍历整条流。BCCCH 实测 **49,689 条**（count 声明 49,766，差 77 为门控尾字段未走通所致，比例 0.15%）；其中 **26,509 条带放置变换**（ObjTransRot(15)=26,500、ObjTransRotScale(16)=9），经 `Transform.Matrix4()` 全部有限。首记录头 `Scale=1,Tris=4,Flags=8,FragmentFlags=256`（N95/N96） | 观察（实现） | `nwd/fragments.go:DecodeFragments`；`TestFragmentsWalk` |
| **N100** | Fragment 子对象分布：约 53% 记录在头字段后带 `readObject` 变换（typeID 14–17），其余子对象布局不同（几何引用 93 或内联索引，未走通）。⇒ 实例变换已可产出（N99），**变换↔几何链接**（哪些几何被哪个 fragment 变换）仍待 | 观察 | II 分布；`TestFragmentsWalk` |

**战役 C 状态**：流/头（N95/N96）+ 逐记录遍历与实例变换（N99/N100）✅；**变换↔几何链接与实例化输出**待续。

## C28 轮（2026-10-13，战役 C：Fragment 头字段语义校正）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N101（校正 N99/N100）** | **`traversableTris`（f64 scale 后的 u32）= 遍历/子树三角计数（聚合量），非该 fragment 自身的三角数**。实测全部 fragment 的该字段之和 ≈ 1.97×10⁸，远大于模型总三角数 1.81×10⁶（约 109×）⇒ 系 culling/遍历聚合值。据此**收紧重同步校验**（traversableScale ∈ (0,1000]），遍历得更精确的 **47,016 条** fragment，其中 **23,839 条带放置变换**（ObjTransRot=23,830、ObjTransRotScale=9）。记录长度仍版本门控（首记录后 gap 多为 176/248B），故遍历基于信封重同步 + scale 校验 | 观察（实现） | `nwd/fragments.go`；`TestFragmentsWalk` |
| **N102** | Fragment 子对象（`readObject`，typeID 14–17 变换）在 align8(头+20) 处；未带变换的记录其子对象偏移受版本门控字段影响 ⇒ 剩余约一半记录的**变换↔几何链接**（geomref 93 / 内联索引）未走通。⇒ 实例变换可产出（N101），**实例化输出与顶点池基准的“按 fragment”变体**仍待 | 观察 | `TestFragmentsWalk`；样本记录字节 |

**战役 C 状态**：流/头（N95/N96）+ 逐记录遍历与实例变换（N99/N101）✅（校正后 47,016 / 23,839）；**变换↔几何链接、实例化输出**待续。**N99/N100 的计数被 N101 取代**。

## C29 轮（2026-10-13，战役 C：fragment↔geometry 链接）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N103** | **`OdNwGraphicGeometryRef`(typeID 93) 文法**（`readElement@0xc66020` + `readUserData@0xc6607c`）：`readElement` = `readUserData()` 后 **`readUInt32` = geometry index**（`setGeomIndex`）。`readUserData` 负载 = `bbox`（2×`FPoint3d` = 2×f32×3 = 24B）→ `align8` → `userOffset`（`DVector3d` = f64×3 = 24B）→ `userScale`（f32）→ `formatVersion>4` 时 `checksum`（u32）。⇒ GeometryRef 尾部 u32 = **几何索引** | 观察 | E2 @0xc66020/@0xc6607c；样本 ref 字节 |
| **N104** | **fragment↔geometry 链接打通**：Fragments 流中 Fragment(13) 记录后随**两个**子对象：变换（14–17）与 GeometryRef（93）。实测 93 计数 26,680；用 N103 定位几何索引，范围 **[1, 24766]**（= 几何流元素规模）⇒ 索引有效。遍历（N101/单遍重同步）得 **23,436 条 fragment 同时带变换与几何索引**（withTransform=23,839、withGeomIndex=23,845、fragments=47,016） | 观察（实现） | `nwd/fragments.go`；`TestFragmentsWalk` |
| **N105** | 剩余约一半 fragment 的变换/索引不落在标准位次（`align8(头+20)` 与「首 93」之外），受版本门控尾字段影响 ⇒ **完整逐记录边界**与**geomIndex→几何元素序号的精确映射**（是否等于几何流元素流序）仍待；但**实例化所需的（变换, 几何索引）对已可产出** | 观察 | `TestFragmentsWalk` |

**战役 C 状态**：流/头（N95/N96）+ 逐记录遍历与实例变换（N101）+ **fragment↔geometry 链接（N104）** ✅；仅剩 geomIndex→几何元素精确映射核对与实例化输出组装。

## C30 轮（2026-10-13，战役 C：fragment↔geometry 映射确证 + U23 定论）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N106** | **geomIndex 为 1-based，映射确证**：GeometryRef 的 bbox（局部）与几何流第 `geomIndex−1` 个元素的 VertexSet 局部 bbox **逐一中心吻合**——平移量 `shift=−1` 时 **100.0% 匹配（15,128/15,128）**，其余 shift 仅 12–17%。⇒ **fragment→geometry 元素映射成立**：`elements[geomIndex-1]`。`FragmentRecord.GeomElementIndex()` 落地 | 观察 | `TestFragmentGeometryLink` |
| **N107** | **U23 定论：索引为“共享/累积池”而非按元素局部**。实测含面元素 7,649 个中，原始索引落在自身顶点数内的仅 **380** 个，**7,269 个越界**（最多超出 1,106）⇒ 元素索引**不按自身顶点局部编号**，而是索引一个跨元素的共享池。⇒ 复盘中“真模型可能是按 fragment 的池”被排除，**累积池 + 元素相对偏移模型保留成立**（与 N79/N98 的边共享 80.7% 一致） | 观察 | `TestMeshValidation`；元素索引统计 |
| **N108** | 综合：几何流 = 全局顶点池（各元素 VertexSet 依序拼接），元素持有指向该池的索引；fragment 以 `GeomIndex`（1-based）引用单个元素并用其变换放置。⇒ **实例化数据齐备**（(变换, 元素) 对 15,128+ 条），实例化输出的“元素→三角”切分需按元素基址+相对索引重组 | 观察 | N79/N98/N104/N106 |

**战役 C 状态**：fragment↔geometry **映射确证（N106）**、U23 **定论（N107：累积池）**、实例数据齐备（N108）。仅剩把 (变换, 元素) 组装为实例化输出。

## C31 轮（2026-10-13，战役 C 收口：实例化语义）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N109** | **NWD 为“共享显示池”，逐元素实例化不成立**。fragment 引用单个几何元素（N106）且含其局部 bbox，但**元素的面索引并非元素局部**：含面元素 7,649 个中仅 **380（5.0%）** 的索引落在自身顶点数内。⇒ fragment 的变换无法作用到“自包含的元素网格”上（同伴元素的顶点共享同一池）。⇒ **实例化以放置元数据形式暴露**（`nwd/instances.go:BuildInstances`：`(ElementIndex, Transform, LocalBBox)`，实测 **23,436 条**），而非逐元素重网格化；这与复盘结论“NWD 适合可视化级直出”一致——单一共享池网格即为正确表示 | 观察 | `TestBuildInstances`；N106/N107 |
| **N110** | 量化顶点路径（`count<0`）**已定 grammar（N73）但当前 `decodeVertexSet` 未实现**（`vc<=0` 直接拒绝）。两真实样本均不触发该路径（v451 恒等、v431 去重池均为正 count）⇒ **无法用现有样本验证**，实现将不可证伪，故**暂不落地**，列为数据受限项 | 观察 | `nwd/elements.go`；样本 |

**战役 C 收口**：fragment 流/头（N95/N96）、逐记录遍历与变换（N99/N101）、fragment↔geometry 映射（N104/N106）、U23 定论（N107）、实例化语义（N109）**全部定案**。战役 C 完成（实例化以元数据交付；共享池下无可重网格化的“实例”）。

## C32 轮（2026-10-13，能力面收口：CLI 暴露 + 数据核查）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N111** | `cmd/nwdinfo` 增补两节：`fragments`（N95–N109：条数/带变换/带几何索引）与 `validation`（N97/N98 网格不变量）。BCCCH 实测 `fragments={47016,23839,23845}`、`validation` 与 N97 一致 ⇒ 新能力（确定性遍历/法线/片段/校验）经 CLI 可达 | 观察（实现） | `cmd/nwdinfo/main.go` |
| **N112** | **本地无其他 NWD/NWC/NWF 样本**（`go-nwd`、`go-dgn`、Downloads、Desktop 仅两份 testdata）。⇒ 战役 F（Text(103)、解析基元、量化顶点路径）所需的触发样本不可得，**确认为样本数据受限**；ODA 运行时为 Linux ELF，macOS 无法执行，E1 外部对拍亦不可得 | 观察 | 文件系统核查 |

**收口状态**：复盘“达到完美所需”五项中 ①②③④⑤ 均已在可得证据内完成（② 以共享池下的实例元数据交付；⑤ 以自洽不变式替代，外部对拍受环境限制）。剩余仅 F 项，**受样本缺失制约**，需业务侧提供含 Text/解析基元/量化顶点的 NWD。

## C33 轮（2026-10-13，战役 D 补齐：MST 亦用真实法线）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N113** | MST 导出改用网格自带逐顶点法线（`MeshNode.Normals = meshNormals(m)`；无则回退 `ReComputeNormal`），与 glTF 一致 ⇒ **法线保真在两种导出格式均落地**。`TestWriteMSTUsesMeshNormals` 断言写入即网格法线（(0,-1,0)）；BCCCH 端到端 MST 写出（54MB，单实例） | 观察（实现） | `export/export.go`；`export_test.go` |

**战役 D 完成**：法线在 MST/glTF 端到端保真（N92–N94/N113）；颜色/UV 受样本数据缺失（N91）。

## C34 轮（2026-10-13，CLI 几何节更新为新解码器）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N114** | `nwdinfo` 的 `geometry` 节改用确定性元素/网格解码器（原用 `LcOpNwdGeometryCompress` 点云路径）。BCCCH 实测：`elements=24766, face_elements=7649, faces=324108, vertices=1354667`（与 findings 台账一致）⇒ CLI 与库解码路径统一 | 观察（实现） | `cmd/nwdinfo/main.go` |

## C35 轮（2026-10-13，战役 F：Text(103) 实现）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N115** | **Text(103) 文法与解码落地**：`OdNwGraphicTextElementReader::readElement@0xc316f4` = `readString<0>`（i32 长度 + UTF-8 + 补 4）→ f32 `xScale`,`yScale`,`rotateAngle` → f32×3 `rotateAxis` → f32×3 `leftPoint` → f32×3 `rightPoint` → i32 `fontId`。新增 `nwd/text.go:decodeTextElement` + `ElementGeometry.Text`；`DecodeElements` 纳入 103。合成单测 `TestDecodeTextElement` 通过（字段、字符串、fontId 端到端） | 观察（实现） | E2 @0xc316f4；`nwd/text.go`；`text_test.go` |
| **N116** | Text 为元数据元素（无三角，需字体轮廓化）；两真实样本不含（N84），故以合成元素验证文法。⇒ 战役 F 的 **Text(103) 关闭**（文法+解码+合成测试） | 观察 | `TestDecodeTextElement` |

**战役 F 状态**：Text(103) ✅（N115/N116，合成验证）；解析基元 Circle/Cylinder 已合成验证（N83/N84）；剩余仅**量化顶点路径**（grammar 已定 N73，样本不触发，实现不可证伪）。

## C36 轮（2026-10-14，U19/U16：模型树 + 属性值文法）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N117** | **LogicalHierarchy 流文法定案**（E2 LogicalHierarchyStreamLoaderImpl::parseStream@0xccf010 + BCCCH 实测）：`[若存在 PartitionProps: i32 块数 + 块×i32][u32 根 marker=100][u32 顶层子数][子×envelope][i32 尾标志]`。根分区节点经 `addToObjectVector(root, marker)` 占据对象向量槽 `marker−100`（addToObjectVector@0xc3b416：槽=marker−100，越界则 push_back；manager+0x1c = 下一 marker 计数）。**PartitionNode 上下文语义**（readElement@0xc47582）：Partition 流（fv>27）不读 children（N57 确认）；LogicalHierarchy 流中首个 PartitionNode 成为上下文根（不读 children），后续的按组节点读 children。**GroupModelItemNode(53)**（readElement@0xc3a216）= ModelItem 中层 + `[u32 子数][子×envelope]` + explicitName 尾串。**GeometryModelItemNode(22)**（readElement@0xc42c5e）= ModelItem 中层 + explicitName，**无 children**（bbox 仅 fv≤30 旧路径）。readObjectVector = `[u32 count][count×readObject]`（readObjectVector@0xc3b8e8）。marker 语义：非 0/1 即新对象，不校验顺序。BCCCH：块表 `[12606,16729,11788,8211,7350,8877,9940,8476,10510,2784]`（和=97271）、顶层 11 子、`LcOpGuidStore = [u32 1][u32 9466][9466×16B GUID]`（8+9466×16 恰好=流长） | 观察 | E2 符号@地址；BCCCH/GateHouse 实测；`nwd/hierarchy.go` |
| **N118** | **PropertyAttribute(86) 真实文法 + readData 定案（U16 收口）**：`[ModelBase][u32 attrFlags][u32 字段数][字段数 × (键对象 + NwDataType + 类型化值)]`（readElement@0xc44828：base → readString → readUInt32 → 循环 readObject(key)+readData）。**readData**（readData@0xc3bd6e）= `[NwDataType 枚举][值]`（E1 NwDataType.h：1 DOUBLE/2 INT32/3 BOOL/4 DISPLAY_STRING/5 DATETIME/6 DOUBLE_LENGTH/7 DOUBLE_ANGLE/8 NAME/9 IDENTIFIER_STRING/10 AREA/11 VOLUME/12 POINT3D/13 POINT2D/14 UINT32/15 INT64/16 UINT64）；实测：浮点类 = align8 + f64（无单位尾标）；NAME(8) = 嵌套 Name 信封（readObject）；NONE(0) = 8 字节；引用型 22 = i32（负=null）。**键对象可为 backref `[1][100+槽]`**（readObject@0xc3b526 先减 0x64 再界检——go-nwd 旧实现缺此偏移已修正）；键亦见 Name 变体 typeID 5/18（Name 文法）。实测 BCCCH 首个属性 17 字段（Name/Type/Family/Category/COBie.* /Structural/Workset）端到端解码、end pos=2060 精确落位。**MaterialAttribute(31)**（readElement@0xc4242c）= base + explicitName + align8 + 4×DRGB(3×f64) + shininess + transparency；**TransformAttribute(39/40/41)**：39 = base+explicitName+align8+DMatrix3d(12×f64)+u32+DVector3d，40 = base+explicitName+align8+DVector3d，41 = base+align8+DVector3d+quaternion+u32 尾（readElement@0xc437c2）；**GraphicMaterialAttribute(200)**（readElement@0xc43daa）= base + （fv≥451：i32 共享节点索引 readSharedObject@0xc3b76e；否则嵌套信封）。nil（marker 0）是属性/子向量中的合法槽位（计数驱动，readObjectVector 对 null 也 push_back）。**剩余长尾**：`Model Lines` 节点族的 Name 变体（typeID 5/18/196/197，含 8 字节对齐的单串变体 196）尚有 4 字节级边界未收敛，容错遍历以 gap 记录 | 观察 | E2 符号@地址；BCCCH 实测（TestPropertyAttributeReadData 等）；`nwd/props.go`/`nwd/objects.go` |
| **N119** | **容错树遍历落地**：`nwd/hierarchy.go:DecodeLogicalHierarchy` 按文法走整树，遇未支持/错位对象记录 Gap 并重同步（扫描 marker∈[100,4200] 且 typeID≤200 的下一信封），交付 `File.DecodeLogicalHierarchyStream` + GuidStore 解码 + nwdinfo `logical_tree`/`guids` 节。BCCCH 顶层首子 = PartitionNode "BCCCH_SITE_LAND.nwc"（guidIndex 5401）；GateHouse 顶层 3 子。 exotic 变体族的 gap 使部分子树以 gap 交付（诚实降级而非硬失败） | 观察（实现） | `TestLogicalHierarchyBCCCH`/`TestLogicalHierarchyGateHouse`/`TestGuidStoreBCCCH`/`TestPropertyAttributeReadData` |
| **N120** | **SpatialHierarchy 流角色定案（U19 收口）**：`SpatialHierarchyStreamLoader::parseStream@0xcff23c` **不读流数据**——仅取 Partition loader 的 `getTreeItem()` 存入 this+0x50；`OdNwSpatialHierarchyStreamContext::getFragment(u32)`@0xcfec72 是 `readStaticItem` 的 fragment 回调数据源。模型树的真实载体是 **LogicalHierarchy**（N117）；空间流为 fragment 索引（N62 的 [count][index] 记录），与 StaticTree(1/2) 组/叶对象共同服务于实例遍历，挂账转为按需（实例化已由 BuildInstances 元数据交付，N109） | 观察 | E2 readElement 调用链；N31/N62/N109 |
| **N121** | **U16 块映射定案**：LogicalHierarchy 头部的 i32 数组即 `getPartPropsBlocks()`@0xb30460 返回的 PartitionProps 块表（N117）；LcOaPartitionProps = PropertyAttribute(86) 对象流（N118 文法），`ScanNames` 的 212 个属性键即其键对象。块值语义（每块属性计数或字节尺寸）与树项的对应关系待对接 LogicalHierarchy 顶层项验证 | 观察（部分） | `TestLogicalHierarchyBCCCH`；`cmd/nwdinfo` |

## C37 轮（2026-10-14，N122：树遍历深度收敛 — 文法修正与真实 FormatVersionEx）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N122** | **树遍历深度收敛**（BCCCH LogicalHierarchy 5MB）：修正四项后对象数 2→**460、树深 7**，"Model Lines"/"Monolithic Landing"/"Landings" 等类目子树完整解出：① **GroupModelItemNode(53)/GeometryModelItemNode(22) 的 readExplisitName 在本批样本的 FormatVersionEx（431/451）下不存在**（门控关闭）——尾串读取曾吞掉后续信封；② **真实 FormatVersionEx 接入**：尾块签名行的 `navisworks:<N>` 词解析为 `Config.NavisworksID`（BCCCH=451、GateHouse=431），`File.FormatVersionEx()` 暴露并驱动类型门控（此前 walk 用合成值 100 导致 GraphicJsonBundle 的 materialJson 门控反转）；③ **GraphicJsonBundle(185) 文法定案**（readElement@0xc36af4）：`[jsonData 字符串][fv>446: materialJson 字符串（可为 null=-1）][u32 条目数][条目数 × (字符串名 + u32 + u32 hasEmbedded，非 0 时 readEmbeddedFile=[串][串][align8][u64 长度][数据])][xref 字符串]`——BCCCH 实测 8 条目纹理路径精确平铺至 73416；④ **readData 宽度以跳转表定案**（readData@0xc3bd6e 表基 0x11750b4，17 case）：NONE(0)=0 字节、浮点类=align8+f64（Variant::Type 是模板常量不读）、BOOL=readBool=rdInt32、NAME(8)=嵌套对象、**未知枚举=0 字节且不报错**（默认分支返回空 OdNwData）。**剩余 gap**：两簇（@58140 起 10KB 与 @73015 起 400B）——涉及 [760][22] GeometryModelItemNode 的字段门控组合（flags=0 时 guid/attrCount 的取舍）与 StaticTree(1/2) 叶，容错遍历以 gap 记录 | 观察 | E2 符号@地址；BCCCH 实测（TestLogicalHierarchyBCCCH：objects>=400、maxDepth>=5）；`nwd/hierarchy.go`/`nwd/objects.go`/`nwd/props.go`/`internal/nwstream/container.go` |

## C38 轮（2026-10-14，N123：树遍历 gap 收敛至 2 个局部缺口）

| ID | 结论 | 态 | 证据 |
|---|---|---|---|
| **N123** | **树遍历 gap 9→2**（BCCCH，objects 460→486）：① **readObjectVector 对 NIL 也 push_back(null)**——对象向量槽位对齐包含 NIL（真实 backref 引用 NIL 槽），go-nwd 原实现 NIL 不入向量导致后续全部 backref slot 前移；② **backref 存储值 = 100+slot**（readObject@0xc3b526 先减 0x64 再界检）；③ **children 恢复路径**：attrCount 在组合门控下可比真实序列少 1（BCCCH "BASE NAVD"/"Site - Sidewalk(JOINTS)" 节点实证：children count 位实为最后一个 attr 的信封 [marker 22][typeID 23 单串对象]）——decodeGroupNode 在 children 解码失败时回滚、补解码一个 attr 并重试 children；④ **readData 权威宽度**以跳转表定案（NONE=0、未知枚举=0、浮点 align8 无尾标、DATETIME/INT64/UINT64 align8、NAME=嵌套对象）；⑤ GraphicJsonBundle(185) 条目循环为 **count 驱动**（[u32 条目数][条目 × (名称+u32+hasEmbedded+可选嵌入文件)]，readElement@0xc36af4 条目计数 8 实测平铺）。**剩余 2 gap**（各 4 字节级局部缺口，resync 覆盖）：@58140 后 +4（GMA/attrCount 组合门控）与 @61820 后 +4（同族）——均不损失后续对象（resync 就近恢复） | 观察 | E2 符号@地址；BCCCH 实测（objects 486 / maxDepth 7 / gaps 2）；`nwd/objects.go`/`nwd/hierarchy.go`/`nwd/props.go` |
