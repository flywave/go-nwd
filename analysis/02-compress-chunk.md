# NWD 压缩与 chunk 层（C2 — TOC 字段语义 + 主负载切分 + 校验）

> 证据级别：E2 静态分析（TNW_Db.tx）。反编译锚点：
> `parseStream@0xbd106e`、`copyStream@0xbd0e20`、`partStream@0xbd0f96`、
> `TOC 循环@0xbd3af8–0xbd3d5a`、`校验@0xbd3e66–0xbd3ef1`、
> `alignPointer<1>@0xbd5195`、`sBlowfishKey@0x16ecfa0`。

## §1 TOC 头（N14）

```
rdInt32  == -1            # 扩展 TOC 标记（必须；否则走 "Read extensions != -1 !" 错误路径）
rdInt32  count            # 流数量
```

旧假设「countA=count」作废；夹具与解析器已按 -1 标记对齐。

## §2 每流记录（N15，parseStream 字段消费端定案）

```
u32 nameLen
nameLen × u8              # 流名（UTF-8）
u32 nameAdler32           # 存档值；滚动校验另算
u32 bitfield              # 低字节 ≠ 0 ⇒ 压缩单块
[align 8]                 # alignPointer<1> = 8 字节对齐（andl $7）
i64 offset                # ★ 绝对文件偏移（def+0x20）
i64 size                  # ★ 区域总长（def+0x28）
i32 prefix                # 前置原始块长（def+0x30；>0 时切出为首 chunk；==4 特殊路径 U6）
i32 suffix                # 尾部裁剪字节（def+0x34）
```

`parseStream` 消费顺序（@0xbd10dd–0xbd13d0）：
1. `seek(file, offset)`；`offset+size` 越界 → 错误 0x91
2. bitfield 低字节 ≠ 0 → `copyStream(file, size)` 整块拷贝（稍后经
   `OdNwCompressedStream`/`NwInflate` 解压）
3. bitfield == 0 → 前置 `prefix` 字节切为首 chunk；`size -= suffix`；余下
   为中段。`prefix==4` 时对 chunk0 走特殊 vtable 路径（U6 挂账）

## §3 TOC 滚动校验 + Blowfish 封印（N16）

- Adler-32 种子 = **1**（`movl $1, -0x18` @0xbd3a13）
- 滚动范围：`name 字节 → bitfield(4) → offset(8) → size(8) → prefix(4) → suffix(4)`
  （对**字段值内存**计算，不含对齐填充）
- 校验值位于 **zlib TOC 之后、尾块内**：8 字节 = Blowfish-ECB（固定 32B 密钥
  `sBlowfishKey@0x16ecfa0`）加密的「u32 acc 双拷贝」u64
- 验证：解密后 low32==high32==滚动 acc；失败 → 错误码 6
- 密钥（rodata，观察级）：
  `f1fbf239dbb788497ae7459fa3f90e8ffa5ab983acecbf66491df232838d6e6b`

## §4 尾块最终布局（修订 N5）

```
[P:...]  签名行 + 8B 对齐
         zlib(TOC)                     # 解压后 = §1+§2
         8B Blowfish(acc)              # §3
[P+N:...] 8B 间隙(U3) + 8B Int64(N) + 52B 页脚
```

## §5 主负载切分（M2 实现映射）

| SDK | go-nwd |
|---|---|
| TOC offset/size/prefix/suffix | `StreamEntry.Offset/Size/Prefix/Suffix` |
| copyStream 压缩单块 | `Container.StreamRaw` + `Inflate`（Go `compress/zlib`） |
| bitfield 低字节 | `StreamEntry.Compressed()` |
| NwAdler32 滚动 | `adler32Update`（自实现，mod 65521） |
| Blowfish 校验 | `verifyTOCChecksum`（`x/crypto/blowfish`） |
| parseStream 越界检查 | `Parse` 内区域合法性验证 |

## §6 已知残项

| ID | 问题 |
|---|---|
| U3 | 尾块后 8B 间隙语义 |
| U4 | ascii 模式尾块签名行是否含 lcodapi/lizlib 词 |
| U6 | prefix==4 的 chunk0 特殊路径（vtable+0x88） |
| U7 | MultiChunk 内部再分块（负载级 chunk 表）——当前按单块处理 |
| U8 | 未压缩流（bitfield==0）中段是否还有内部帧格式 |
