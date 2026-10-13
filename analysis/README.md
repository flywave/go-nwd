# go-nwd — NWD（Autodesk Navisworks）纯 Go 解析库

NWD 格式的分析与实现**独立于 go-dgn / go-rvt**，同级仓库。
证据源：ODA BimNv SDK（`go-dgn/ODA-Parse-DWGs-main/ODAToolkit/`）。

## 决策记录

| 项 | 决定 |
|---|---|
| 与 go-dgn/go-rvt 关系 | 独立 module（`github.com/flywave/go-nwd`）；内部字节原语按需复制 |
| 优先级 | M1 元数据（识别+版本+流清单）→ M2 chunk/压缩层 → M3 模型树 → M4 几何 → M5 属性/CDA |
| 验证方式 | 现阶段纯静态分析（E1 头文件 + E2 二进制）；样本到位后字节级 golden 验证 |
| 样本 | 暂无（征集中心：业务侧 NWD/NWC/NWF；或用 ODA Visualize2Nwd 导出最小样本） |
| SDK | `go-dgn/ODA-Parse-DWGs-main/ODAToolkit/`（ODA 2026，BimNv 头文件 + TNW_Db.tx Linux x64 未 strip） |

## 分析产出（证据 → 文档）

| 文档 | 内容 | 阶段 |
|---|---|---|
| `analysis/README.md` | 本索引 | — |
| `analysis/findings.md` | 结论台账（N 系列） | 持续 |
| `analysis/00-sdk-inventory.md` | ODA BimNv 模块地图 + 二进制清单 | C0 ✅ |
| `analysis/01-container.md` | **格式总纲：文件头/签名/版本/StreamSplitter/TOC** | C1 ✅ 主体 |
| `analysis/02-compress-chunk.md` | **TOC 字段语义 + 主负载切分 + Adler/Blowfish 校验** | C2 ✅ 主体 |
| `analysis/03-model-tree.md` | **对象信封 + 类型注册表 + 节点 Schema** | C3 ✅ 主体 |
| `analysis/rea-extract-plan.md` | REA 提取清单（P0–P3） | 持续 |

## 实现路线

1. ✅ **M1 识别+元数据（骨架落地）**：`internal/nwstream`（三签名识别 + v8 footer/TOC 解析 + 8B 对齐）
   → `nwd.Open`（版本门控+流清单）→ `cmd/nwdinfo` JSON；合成夹具单测绿
   - 未竟：真实样例验证；v2–7 LoadOld 路径；ascii vs navisworks 尾块词法（U4）
2. ✅ **M2 chunk/压缩层（落地）**：TOC 字段定案（offset/size/prefix/suffix/bitfield，
   N14–N17）+ Adler-32 滚动校验 + Blowfish 封印验证 + 每流 `StreamData`
   （压缩=zlib 解压 / 未压缩=中段直读）；夹具支持 Compressed/Prefix/Suffix
   - 未竟：prefix==4 特殊路径（U6）；MultiChunk 内部再分块（U7）；真实样例
3. ✅ **M3 模型树（骨架落地）**：对象信封（nil/backref/new-marker≥100）+
   NwObjectType 110 条注册表（GOT 重定位提取）+ 字符串 codec（i32+UTF-8+align4）
   → ModelBase/Name/ModelItemNode/PartitionNode/GroupModelItemNode 解码器
   → `File.DecodeTree` + `nwdinfo` 树输出；夹具端到端绿
   - 未竟：FormatVersionEx 门控全档（U10）；StaticTree 空间层次（U11）；
     属性/Transform 对象解码（U9 余量）；真实样例
4. ⬜ **M4 几何**：GeometryCompress（精度还原）+ Fragments + Shell
5. ⬜ **M5 属性/CDA**：CommonSchemas 字段树 + PartitionProps

## 包结构

```
internal/nwio/      字节读取原语（LE）
internal/nwstream/  签名识别 + StreamSplitter 容器（v8 footer/TOC）
nwd/                Open/Metadata（流清单）；tree/geometry/props 按里程碑追加
cmd/nwdinfo/        CLI：nwdinfo <file.nwd> → JSON
```

## 方法与证据约定

同 go-dgn/go-rvt：观察/推断/未知三态；E1=头文件源码、E2=二进制静态分析（符号名+地址）、E3=样例实测。
证据 ID 引用 `E1 文件:行` / `E2 符号@地址` / 样例偏移。
