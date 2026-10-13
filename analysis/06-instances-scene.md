# NWD 实例与场景装配（C6 — 变换对象 + 场景模型）

> 证据级别：E2 静态分析（TNW_Db.tx）。锚点：
> `OdNwObj{Translation,TransRot,TransRotScale,Matrix}Reader::readElement`、
> (anonymous) `readMatrix{Full,Linear,Translation}`、
> `OdNwFragmentReader::readElement@0xc5cac6`、
> `OdNwStaticTreeGroupReader::{readElement@0xc6033a,readStaticItem@0xc603b2,readTreeItem@0xc60740}`。

## §1 版本门控阈值总表（N30，跨 M3–M6 收口）

reader 代码中的字面门槛（`getFormatVersion` 比较），全部为观察级：

| 阈值 | 出现处 | 语义 |
|---|---|---|
| 0x15 = 21 | ModelBase/PartitionNode/… | 低版本跳过新字段 |
| 0x57 = 87 | FragmentReader | Fragment 字段分档 |
| 0xD6 = 214 | ModelItemNode | guidIndex 分档 |
| 0xF2 = 242 | FragmentReader | Fragment flag 掩码分档 |
| 0xF8 = 248 | ModelItemNode | 中层门控字段 |
| 0x1C3 = 451 | readSharedObject | 共享对象解析开关 |

Fragment 版本门控中的 flag 掩码（观察级）：
- `>242`：flags &= `0x6FFD3FFF`
- `≤242`：flags &= `0x6FFD3F7F`
- `≤87`：flags >>= 24; & 0xF

⇒ `NwFormatVersionEx` 为**流内读取**（`readEnum<FormatVersionEx>`=rdInt32），
具体档位常量未在符号/rodata 暴露（U10，需真实样例或 ODA 文档）。

## §2 变换对象（N32，四个类型定案）

`readElement` 均以 `alignPointer()` 起始，随后类型化 payload：

| typeID | 类 | payload | E2 证据 |
|---|---|---|---|
| **14** | ObjTranslation | `3×f64`（OdGeVector3d） | setTranslation；readMatrixTranslation=rd3Doubles |
| **15** | ObjTransRot | `3×f64` 平移 + `4×f64` 四元数 | setTranslation+setRotation(OdGeQuaternion)、readQuaternion |
| **16** | ObjTransRotScale | `3×f64` + `4×f64` + `f64` 缩放 | setScale(double)、readDouble |
| **17** | ObjMatrix | 逐元素 `f32` 4×4（cl(i,j) 赋值） | readFloat×N + Matrix3d::cl(i,i) |

辅助（匿名命名空间）：`readMatrixFull`=rdDoubles(N)、`readMatrixLinear`=rd3Doubles×3、
`readMatrixTranslation`=rd3Doubles。

go-nwd：`Transform` 模型 + `Matrix4()`（四元数→行主序 4×4 组合）。

## §3 Fragment（typeID 13）版本门控结构（N25 补强）

`readElement@0xc5cac6` 观测（对齐后）：
```
f64 traversableScale        # 前置
u32 traversableTris
[flag] u32 …
u32 fragmentFlags           # 写入 getFragmentFlags()
[v>87 / v>242 掩码清理]
u8 primitives
… readObject（变换 14–17 / 几何引用 93）
readObject RunPath
```
精确位义与可选字段序 → U14（真实样例）。

## §4 空间层次 StaticTree（N31，部分）

- `readElement@0xc6033a`（Group）/`0xc62ee2`（Leaf）
- `readStaticItem@0xc603b2`：`i32`（项索引/类型）+ `function<OdNwFragment*(u32)>`
  片段查找回调 + `isShape` 分支 → 建 `StaticTreeLeaf` / 递归组；
  `calcBoundingBox`+`NwTreeItem::update`
- `readTreeItem@0xc60740`：通用项读取（组/叶分发）
- 精确项布局与 `NwTreeItemType` 取值 → U11（真实样例）

## §5 场景装配（go-nwd M6）

`nwd/scene.go`：`BuildScene(tree, mesh)` 深度遍历分区树 →
扁平 `SceneInstance{Name, Path, Transform, Mesh}`。
- 节点名优先 userName，回退 displayName/name
- 单几何夹具下 mesh 附着到每个实例；per-node 几何绑定 = U16
- `File`/`nwdinfo` 输出 `scene`

## §6 实现映射

| SDK | go-nwd |
|---|---|
| Obj{Translation,TransRot,TransRotScale,Matrix}Reader | `nwd/transform.go` `Transform` + `decodeTransform` |
| readMatrixTranslation/Linear/Full | `read3Doubles`/`readQuaternion`/`f64` |
| StaticTree Group/Leaf | 文档（U11） |
| Fragment | 文档（U14）；`Object` 保留 transform/attribute |
| 场景 | `nwd/scene.go` `BuildScene` |

残项：U10（FormatVersionEx 档位常量）、U11（StaticTree 精确布局）、
U14（Fragment 位义）、U17（ObjMatrix 元素数 12/16）。
