# 计划目标：完全解决 NWD 面/基元/属性层的缺口

> 来源：C19 复盘（“容器与顶点层可靠；面层可用但非完美；属性/材质层缺失”）。
> 原则不变：**E1 头文件优先 → E2 反汇编定案 → E3 真实样本验证 → 单测回归**。
> 每个战役的交付：可测试原语（Go）+ 两个真实样本（BCCCH v451 / GateHouse v431）上的量化验收 + findings 编号。
>
> 关键资产：`go-dgn/ODA-Parse-DWGs-main/ODAToolkit/bin/lnxX64_11dll/TNW_Db.tx`
> （32MB ELF，**not stripped**，`nm -C`/`objdump -d` 可直取）。头文件 `BimNv/Include/**`（E1）。

## 缺口 → 战役映射（总览）

| 复盘缺口 | 战役 | 交付 | 验收 |
|---|---|---|---|
| 面数组“启发式定位器”非确定性；BCCCH 47%、GateHouse 0 命中 | **A. 确定性元素遍历** | 子对象 reader 全解 + 信封驱动解码器 | 带面元素命中率≥99%；v431 命中>0 |
| 大多边形语义（polygon/strip/fan、绕序）未证 | **B. 面语义** ✅N85 | 三角带展开 | 单测 + 与 SDK 一致 |
| 顶点空间基准 U23（累积池 vs 按 fragment）| **C. Fragments/顶点基准** | Fragment 记录文法 + 定位规则 | 索引越界消失；实例变换落地 |
| 逐元素法线/颜色/UV 缺失 → 材质/颜色丢失 | **D. 属性保真** | ColorSet/NormalSet/TexCoord 解码 | glTF 含 NORMAL/COLOR_0/TEXCOORD_0 |
| 无独立参照验证 | **E. 参照对拍** | ODA 转储/自洽不变量对拍 | 逐元素差异表 |
| Text(103)、解析基元真实样本、量化顶点路径 | **F. 边角** | 按需 | 合成 + 真实 |

---

## 战役 B（已完成，N85/N86）

- **B1** ✅ E2 定案：`OdNwGeometryShellImpl::createTriangleFaces@0x10e1776`。
  每个面按**三角带滚动窗口**展开：`p[0..n-1]`，`k=0..n-3`，偶 `k`→`(p[k],p[k+1],p[k+2])`，奇 `k`→`(p[k+1],p[k],p[k+2])`。
  字段：`+0x58`=verticesPerLine（`setVerticesCountPerFace@0x10e1e62`）、`+0x60`=indexesPerLine（`setIndexes@0x10e1e38`）。
- **B2** ✅ 落地 `StripTriangles`（`nwd/faces.go`）、`DecodeMesh` 改带展开（`nwd/mesh.go`）；单测 `TestStripTriangles`、`TestRealMesh` 绿。
- **B3**（可选）用真实样本做流形度检验：统计边被 2 个三角共享的比例（带 vs 扇），作为带语义的 E3 佐证。

## 战役 A（最大缺口，P0）— 确定性元素遍历

复盘中“47% 命中 / GateHouse 0 命中”的根因：`locateFaceArrays` 是**从元素内盲搜**自洽的 vpl+ipl，且只识别 `NormalSetShort` 一种子对象，遇到 v431 的不同子对象布局即失效。

**A1 反汇编 4 个子对象 reader 的精确文法（字节长度 + 压缩变体）**
| 子对象 | 符号 | 地址 |
|---|---|---|
| VertexSet | `OdNwGraphicVertexSetReader::readElement` | `0xc26590` |
| TexCoordSet | `OdNwGraphicTexCoordSetReader::readElement` | `0xc29ad0` |
| ColorSet | `OdNwGraphicColorSetReader::readElement` | `0xc201b4` |
| NormalSetShort | `OdNwGraphicNormalSetShortReader::readElement` | `0xc21e74` |
| NormalSetFloat | `OdNwGraphicNormalSetFloatReader::readElement` | `0xc22926` |

要回答：每种集合的**字段序、每分量宽度、压缩（precision-reduced）分支的字节长度**，从而能**精确推进游标**。

**A2 反汇编元素读取顺序与门控**
`OdNwGraphicTriangleSetElementReader::readElement@0xc2c1ea`：确证 4 个嵌套 `readObject` 的顺序与“缺失即不写”的判定；`readVertexesPerLine@0xc2ecd4` 前的 **align4**；`fmtVer>0x13(19)` 才 `readIndexesPerLine@0xc2c918` 的门控。

**A3 实现信封驱动解码器（替换启发式）**
- 新增 `readEnvelope(data,pos) (typeID,payloadPos,ok)`：`marker=0`→nil（+4）、`1`→回指（+8）、`≥100`→`typeID=u32`。
- 子对象循环：按 typeID 分派 `decodeVertexSet/decodeNormalSet*/decodeColorSet/decodeTexCoordSet`，各自返回消费长度并推进。
- 子对象结束后依次 `ReadVertexesPerLine` → `Align4` → `ReadIndexesPerLine`。
- **确定性验收**：面数组必须以“恰好落在元素边界 `e`”结束（含已知尾部 padding）；否则该元素标记为“子对象未支持”而非盲搜。

**A4 量化验收**
- BCCCH：带面元素命中率 47% → 预期 ~100%；`Σvpl==len(ipl)` 全通过；三角数保持 1,806,959±（带/扇同数）。
- GateHouse：面命中 0 → >0（解出真实三角/线）。
- 回归：`TestRealMesh`、新增 `TestDeterministicElements`（两样本）。

**A5 执行结果（C22，N87–N90）** ✅
- 子对象文法与“4 个位次信封”结构定案（N87/N88）；`nwd/subobjects.go` 落地确定性遍历。
- 确定性遍历在 BCCCH 全 14528 个带 VertexSet 元素上与旧扫描**逐元素一致**（`differ=0`）⇒ 误匹配风险排除（N89）。
- **重要归因**：BCCCH “未命中”的 6726 个 type-94 元素**其面表为空**（`[i32 n=0]`，零三角）；GateHouse v431 的 17 个 type-94 元素**全部为空面** ⇒ “47% / v431 0 命中”**不是定位器缺陷**，而是真实数据无三角面（N90）。
- 结论：战役 A 的核心风险（启发式非确定、53% 未解释、v431 未通、误匹配）**关闭或归因**。后续重点转向 D（属性/材质）、C（fragments/实例）。

## 战役 C（P0）— Fragment / 顶点基准 U23

- **C1** 反汇编 `OdNwFragmentsStreamLoader`：`createStreamLoader@0xcb8672`、`parseStream`（ST `0xcb921e`/`0xcb993e`、MT `0xcc54f2`），还原 Fragment 记录文法（count + 记录：geometryId/geometryIndex、lowBound/highBound、transformation、material、isSolid）。
- **C2** 反汇编 `OdNwFragmentReader::readElement@0xc5cac6` 与 `OdNwFragmentImpl::setGeometry*`（`setGeometryIndex@0x1084fb4`、`setGeomtryRefOffset@0x10859ac`），确证 Fragment→几何的引用方式与偏移语义。
- **C3** 判定 U23：顶点池是“**流级累积池 + 元素相对索引**”还是“**按 fragment/共享节点的局部池**”。现有证据（element0 索引引用 element1 顶点、avg edge 4.14 vs 49.99）支持前者，但需 `validateIndices@0x10de390`（仅 resize(maxIdx+1)）+ SharedNodes 流配合确证。
- **C4** 实现实例化：Fragment 变换 × 几何 → 场景图（替换当前单实例直出）。
- 验收：BCCCH 每个三角的 3 个顶点均落在同一 fragment 的 bbox 内（当前相对模型下应成立）；场景实例数≈ Fragment 记录数。

## 战役 D（P0/P1）— 属性/材质保真

- **D1** ColorSet 逐顶点颜色（`readColors + u8 通道宽`；压缩变体）→ glTF `COLOR_0`。
- **D2** NormalSetShort/Float 逐顶点法线 → 替代计算平滑法线（导出 MST/glTF 的 `NORMAL`）。
- **D3** TexCoordSet(61)（`OdGePoint2d`）→ `TEXCOORD_0`。
- **D4** `MaterialElement`/透明度 → glTF PBR 材质；`NwGraphicMaterialAttribute`（E1）字段表先行。
- 验收：导出 glTF 两样本元素法线/颜色计数 >0；材质数 >0。

## 战役 E（P1）— 独立参照对拍

- **E1** 首选 ODA 自带转储器 `BimNv/Extensions/NwDumper/NwGeometryDumper.cpp`（源码在仓）作为**算法参照**；若可运行 `NwDumper.tx`/`NwGeom2Shell.tx`（需 Linux ODA 运行时），对同一样本转储为**逐元素对拍基准**。
- **E2** 无运行时则以**自洽不变量**替代：流形度、三角面积守恒、bbox、索引覆盖、`Σvpl==ipl`。
- 验收：输出逐元素差异表（顶点/面/属性），差异仅来自已知未支持类型。

## 战役 F（P2/P1）— 边角

- **F1** Text(103)：`OdNwGraphicTextElementReader@0xc316f4`（需字体，低优先）。
- **F2** 解析基元（Circle 104/Cylinder 105）：寻含 104/105 的真实样本以覆盖合成单测无法证明的路径。
- **F3** Spatial/Logical 完整层级（U19/U11）；GeometryCompress 设置流（U20/U22）按需（N71 已证与顶点压缩无关）。
- **F4** 量化顶点路径（负 count，N73/N75 `readBits`）：构造/寻找触发样本验证。

---

## 执行顺序与状态

1. **B** 面语义 ✅（N85/N86）。
2. **A** 确定性遍历 ✅（N87–N90；“47%/GateHouse 0”归因为空面元素）。
3. **D** 属性保真 ✅（N91–N94；法线端到端，颜色/UV 样本数据缺失）。
4. **C** Fragments ✅：流/头（N95/N96）、逐记录遍历与变换（N99/N101）、fragment↔geometry 映射（N104/N106，100% bbox 吻合）、U23 定论（N107，累积池）、实例化语义（N109，共享池下以放置元数据交付 `BuildInstances`）。
5. **E** 参照验证 ✅/限定：E2 自洽不变量 ✅（N97/N98）；E1 外部对拍受运行环境限制不可得。
6. **F** 边角：Text(103) ✅（N115/N116，合成验证）；解析基元 ✅ 合成（N83/N84）；量化顶点路径 🔶（grammar 已定 N73；样本不触发，实现不可证伪，暂缓）。

## 证据与文档约定

- 每条结论入 `analysis/findings.md`（N 系列），三态：观察 / 推断 / 未知；E2 引用“符号@地址”。
- 代码原语落 `nwd/faces.go`（vpl/ipl/bits）、新增 `nwd/subobjects.go`（子对象 reader）等；导出面 `export/`。
- 真实样本测试在 `nwd/real_test.go`，缺样本自动跳过。
