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
| U18 | 真实属性类型 payload 全表（PublishAttribute 92 已探部分；余 70/76/79/86/88/180 等按真实流校正） | P0 | M3/M5 收口 | 开（样本已解锁） |
| U19 | Partition 流完整对象图（attrCount>0 的属性序列与子节点/变换） | P0 | M3 收口 | 开 |
| U20 | GeometryCompress 几何块容器（Blowfish 8B，块表校验）与 Geometry 流真实内容 | P0 | M4 收口 | 开 |
