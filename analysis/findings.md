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
