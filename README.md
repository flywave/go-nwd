# go-nwd

Go implementation of the Autodesk Navisworks NWD file format (container
v8), built from reverse-engineering the ODA BimNv `TNW_Db.tx` module.

## Status

- **M1 ✅**: 签名识别、容器版本门控、v8 footer/尾块布局、TOC 解析、流清单
- **M2 ✅**: TOC 字段语义定案（offset/size/prefix/suffix/压缩位）、
  Adler-32 滚动校验 + Blowfish 封印验证、每流 `StreamData`
- **M3 ✅ 骨架**: 对象信封（nil/回指/新对象 marker≥100）、NwObjectType
  110 条注册表、UTF-8 字符串 codec、Partition/Group 节点解码器、
  `File.DecodeTree` + `nwdinfo` 树输出
- **M4 ✅ 骨架**: GeometryCompress 块容器（Blowfish-8B 解密）、
  顶点集未压缩解码、Mesh 装配、`nwdinfo` mesh 输出
- **M5 ✅ 骨架**: NwSchemaFieldType 枚举、CommonSchemas 流解码
  （Schema/Field/concepts）、属性对象解码（Text/URL/GUID/Binary/
  UInt64/Property）、`nwdinfo` schemas 输出
- **M6 ✅ 骨架**: 版本门控阈值总表、变换对象（14–17：平移/旋转/缩放/矩阵）、
  `Transform.Matrix4()`、`BuildScene` 场景装配、`nwdinfo` scene 输出
  —— 夹具端到端绿；FormatVersionEx 档位常量、StaticTree、Fragment 位义待样本（U10/U11/U14）

## Layout

- `nwd/` — 公共 API：`Detect` / `Open` / `Metadata` / `DecodeTree` /
  `DecodeGeometryBlocks` / `DecodeSchemas` / `BuildScene` / 对象信封
- `internal/nwstream/` — 签名 + StreamSplitter 容器（v8 footer/TOC/校验）
- `internal/blowfish/` — 自包含 Blowfish 实现（仅用于兼容 NWD 内置密钥封存）
- `internal/nwio/` — 小端字节读取原语
- `cmd/nwdinfo` — JSON 转储 CLI（分区树 / 网格 / schema / 场景）
- `cmd/nwdgen` — 合成 v8 夹具生成器（调试/演示用）
- `analysis/` — 逆向文档（E1/E2 证据台账，不属 Go module）

## Usage

```go
import "github.com/flywave/go-nwd/nwd"

kind := nwd.Detect(buf) // KindASCIILichunk / ...
f, err := nwd.Open(buf) // Metadata + payload access
tree, err := f.DecodeTree(f.StreamByName("LcOpNwdPartition"))
scene := nwd.BuildScene(tree, nil)
```

CLI:

```sh
go run ./cmd/nwdinfo file.nwd
```

## Testing

```sh
go test ./...
```

合成夹具由 `internal/nwstream.BuildSyntheticV8` 按 `analysis/01-container.md`
构造；真实 NWD 样本到位后追加 golden 测试。

## Sample request（真实样本征集）

为验证并加固以下 NWD 能力，欢迎业务侧提供真实样本
（`.nwd` / `.nwc` / `.nwf`，放入 `nwd/testdata/` 并注明来源脱敏级别）：

1. **现代 v8 容器**：Navisworks 2020+ 导出的发布模型（验证 TOC 字段语义
   与 chunk 布局，findings U1/U2）
2. **多版本矩阵**：2013–2016（可能走 LoadOld v2–7 路径）、2018/2019
3. **NWC 缓存 / NWF 集合**：对照 `NwFileType` 三态
4. **带属性/CDA 与几何的大文件**：驱动 M4/M5

样本只读解析，不外发。联系 go-nwd 维护者即可。

## Evidence convention

同 go-dgn / go-rvt：观察/推断/未知三态；E1=头文件、E2=二进制静态分析
（符号@地址）、E3=样例实测。结论台账见 `analysis/findings.md`（N 系列）。
