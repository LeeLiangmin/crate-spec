# crate-spec 项目概览

**crate-spec** 是一个 Rust 工具，用于生成和验证 `.scrate` 文件。该格式在标准 `.crate` 基础上增加了签名和完整性校验，支持镜像/缓存场景下的端到端数据完整性与认证。

---

## 📑 目录

- [项目结构](#项目结构)
  - [目录组织](#目录组织)
- [核心模块分析](#核心模块分析)
  - [1. 二进制格式](#1-二进制格式-srcutilspackage)
  - [2. 包上下文](#2-包上下文-srcutilscontextrs)
  - [3. 编码流程](#3-编码流程-srcutilsencoders)
  - [4. 解码流程](#4-解码流程-srcutilsdecoders)
  - [5. PKCS7 签名](#5-pkcs7-签名-srcutilspkcsrs)
  - [6. TOML 解析](#6-toml-解析-srcutilsfrom_tomlrs)
  - [7. 打包逻辑](#7-打包逻辑-srcpackrs)
  - [8. 解包逻辑](#8-解包逻辑-srcunpackrs)
  - [9. 命令行接口](#9-命令行接口-srcmainrs)
- [执行流程](#执行流程)
  - [编码流程（生成 .scrate）](#编码流程生成-scrate)
  - [解码流程（验证并提取 .crate）](#解码流程验证并提取-crate)
- [安全机制](#安全机制)
- [测试示例](#测试示例)
- [技术栈](#技术栈)
- [设计特点](#设计特点)
- [代码索引](#代码索引)

---

## 项目结构

### 目录组织

```
crate-spec/
├── src/
│   ├── main.rs          # 命令行入口
│   ├── lib.rs           # 库入口
│   ├── pack.rs          # 打包（编码）逻辑
│   ├── unpack.rs        # 解包（解码）逻辑
│   └── utils/
│       ├── mod.rs       # 工具模块导出
│       ├── context.rs   # 包上下文数据结构
│       ├── encode.rs    # 编码实现
│       ├── decode.rs    # 解码实现
│       ├── from_toml.rs # TOML解析器
│       ├── pkcs.rs      # PKCS7签名/验证
│       └── package/     # 二进制格式定义
│           ├── mod.rs   # 包结构定义
│           ├── bin.rs   # 编码/解码trait
│           └── gen_bincode.rs # Bincode序列化实现
├── test/                # 测试文件
│   ├── example/         # 示例脚本
│   └── test.toml        # 测试用的TOML文件
├── Cargo.toml           # 项目配置
└── README.md            # 项目文档
```

---

## 核心模块分析

### 1. 二进制格式 (`src/utils/package/`)

`.scrate` 文件结构：

```
+-------------------+
| Magic Number      | 5字节: [0x43, 0x52, 0x41, 0x54, 0x45] ("CRATE")
+-------------------+
| CrateHeader       | 版本、偏移量、大小信息
+-------------------+
| StringTable       | 字符串表（去重，用偏移量引用）
+-------------------+
| SectionIndex      | 段索引表（指向各个数据段）
+-------------------+
| DataSections      | 数据段集合
|   - PackageSection      (类型0) 包信息
|   - DepTableSection     (类型1) 依赖表
|   - CrateBinarySection  (类型3) 原始.crate二进制
|   - SigStructureSection (类型4) 签名结构（可多个）
+-------------------+
| Fingerprint       | 32字节SHA256指纹（文件末尾）
+-------------------+
```

**关键数据结构：**
- `CratePackage`: 顶层结构
- `CrateHeader`: 文件头，包含各段偏移和大小
- `SectionIndex`: 段索引
- `DataSection`: 枚举，包含四种数据段类型
- `StringTable`: 字符串去重表

**相关文件：**
- [`src/utils/package/mod.rs`](src/utils/package/mod.rs) - 数据结构定义
- [`src/utils/package/gen_bincode.rs`](src/utils/package/gen_bincode.rs) - 序列化实现
- [`src/utils/package/bin.rs`](src/utils/package/bin.rs) - 编码/解码trait

---

### 2. 包上下文 (`src/utils/context.rs`)

`PackageContext` 是核心数据结构，包含：

- `pack_info`: 包信息（名称、版本、许可证、作者）
- `dep_infos`: 依赖信息列表
- `crate_binary`: 原始 `.crate` 文件二进制
- `sigs`: 签名信息列表
- `root_cas`: 根CA证书列表（用于验证）

**签名类型：**
- `SIGTYPE::FILE`: 对整个文件签名
- `SIGTYPE::CRATEBIN`: 仅对 crate 二进制签名

**相关文件：**
- [`src/utils/context.rs:24`](src/utils/context.rs#L24) - PackageContext 定义

---

### 3. 编码流程 (`src/utils/encode.rs`)

编码分为三个阶段：

#### 阶段1：签名前准备
```rust
encode_to_crate_package_before_sig()
```
- 设置魔数
- 写入包信息、依赖表、crate二进制
- 写入占位签名段（全0）
- 构建段索引和字符串表
- 设置文件头

#### 阶段2：计算签名
```rust
encode_sig_to_crate_package()
```
- 计算每个签名的摘要（SHA256）
- 使用PKCS7对摘要签名
- 替换占位签名段

#### 阶段3：签名后处理
```rust
encode_to_crate_package_after_sig()
```
- 更新段索引和文件头
- 计算指纹（SHA256，排除末尾32字节）
- 将指纹写入文件末尾

**相关文件：**
- [`src/utils/encode.rs:173`](src/utils/encode.rs#L173) - 编码主函数
- [`src/utils/encode.rs:115`](src/utils/encode.rs#L115) - 签名计算

---

### 4. 解码流程 (`src/utils/decode.rs`)

解码步骤：

1. **指纹验证**
   ```rust
   check_fingerprint()
   ```
   - 计算文件（除末尾32字节）的SHA256
   - 与文件末尾指纹比对

2. **解析二进制结构**
   - 解析 `CratePackage`
   - 读取字符串表
   - 解析各数据段

3. **签名验证**
   ```rust
   check_sigs()
   ```
   - 根据签名类型计算实际摘要
   - 使用根CA验证PKCS7签名
   - 比对摘要

4. **提取数据**
   - 恢复包信息、依赖、crate二进制

**相关文件：**
- [`src/utils/decode.rs:154`](src/utils/decode.rs#L154) - 解码主函数
- [`src/utils/decode.rs:129`](src/utils/decode.rs#L129) - 签名验证

---

### 5. PKCS7 签名 (`src/utils/pkcs.rs`)

`PKCS` 封装签名与验证：

- `encode_pkcs_bin()`: 对消息摘要进行PKCS7签名
- `decode_pkcs_bin()`: 验证PKCS7签名并提取原始摘要
- `gen_digest_256()`: SHA256摘要

**相关文件：**
- [`src/utils/pkcs.rs`](src/utils/pkcs.rs) - PKCS7实现

---

### 6. TOML 解析 (`src/utils/from_toml.rs`)

`CrateToml` 从 `Cargo.toml` 提取：

- 包信息（name, version, license, authors）
- 依赖信息（name, version, source type, platform）

**支持的依赖源类型：**
- `CratesIo`: crates.io
- `Git`: Git仓库
- `Url`: URL
- `Registry`: 自定义注册表
- `P2p`: P2P源

**相关文件：**
- [`src/utils/from_toml.rs`](src/utils/from_toml.rs) - TOML解析器

---

### 7. 打包逻辑 (`src/pack.rs`)

`Packing` 结构体处理打包：

1. `cmd_cargo_package()`: 调用 `cargo package --allow-dirty`
2. `read_crate()`:
   - 解析 `Cargo.toml`
   - 读取生成的 `.crate` 文件
   - 构建 `PackageContext`

**相关文件：**
- [`src/pack.rs:84`](src/pack.rs#L84) - 打包入口函数

---

### 8. 解包逻辑 (`src/unpack.rs`)

`Unpacking` 结构体处理解包：

- 加载根CA证书
- 调用 `PackageContext::decode_from_crate_package()` 解码
- 返回验证后的 `PackageContext`

**相关文件：**
- [`src/unpack.rs:35`](src/unpack.rs#L35) - 解包入口函数

---

### 9. 命令行接口 (`src/main.rs`)

使用 `clap` 解析命令行参数：

**编码模式 (`-e`):**
- `-r`: 根CA文件路径（可多个）
- `-c`: 发布者证书路径
- `-p`: 发布者私钥路径
- `-o`: 输出目录
- `<project path>`: Rust项目路径

**解码模式 (`-d`):**
- `-r`: 根CA文件路径（可多个）
- `-o`: 输出目录
- `<.scrate file path>`: `.scrate` 文件路径

**相关文件：**
- [`src/main.rs:38`](src/main.rs#L38) - 命令行入口

---

## 执行流程

### 编码流程（生成 .scrate）

```
1. 解析命令行参数
   ↓
2. 验证必需参数（证书、私钥、根CA）
   ↓
3. pack_context() - 打包上下文
   ├─ 调用 cargo package
   ├─ 解析 Cargo.toml
   └─ 读取生成的 .crate 文件
   ↓
4. 加载PKCS签名器
   ├─ 加载证书
   ├─ 加载私钥
   └─ 加载根CA
   ↓
5. 添加签名到PackageContext
   ↓
6. encode_to_crate_package() - 编码
   ├─ 阶段1: 签名前准备（写入数据，占位签名）
   ├─ 阶段2: 计算并写入真实签名
   └─ 阶段3: 计算并写入指纹
   ↓
7. 写入 .scrate 文件到输出目录
```

**关键函数调用链：**
- [`src/main.rs:63`](src/main.rs#L63) → `pack_context()`
- [`src/pack.rs:84`](src/pack.rs#L84) → `Packing::pack_context()`
- [`src/utils/encode.rs:173`](src/utils/encode.rs#L173) → `encode_to_crate_package()`

---

### 解码流程（验证并提取 .crate）

```
1. 解析命令行参数
   ↓
2. 验证必需参数（根CA）
   ↓
3. 读取 .scrate 文件二进制
   ↓
4. unpack_context() - 解包上下文
   ├─ 加载根CA证书
   └─ decode_from_crate_package() - 解码
       ├─ 验证指纹（完整性检查）
       ├─ 解析二进制结构
       ├─ 验证签名（身份验证）
       └─ 提取数据到PackageContext
   ↓
5. 提取 .crate 文件到输出目录
   ↓
6. 导出元数据到 {name}-{version}-metadata.txt
```

**关键函数调用链：**
- [`src/main.rs:96`](src/main.rs#L96) → `unpack_context()`
- [`src/unpack.rs:35`](src/unpack.rs#L35) → `Unpacking::unpack_context()`
- [`src/utils/decode.rs:154`](src/utils/decode.rs#L154) → `decode_from_crate_package()`

---

## 安全机制

### 完整性保护
- 文件末尾32字节SHA256指纹
- 传输或存储错误会被检测

### 身份认证
- PKCS7数字签名
- 根CA证书链验证
- 支持对文件或仅对crate二进制签名

### 签名灵活性
- 支持多个签名
- 两种签名类型（文件级/二进制级）

---

## 测试示例

项目包含测试脚本（`test/example/`）：

- **encode_crate.sh**: 编码示例
- **decode_crate.sh**: 解码示例
- **hack_file.sh** + **hack.py**: 完整性测试
  - 模式0: 修改文件字节（会被指纹检测）
  - 模式1: 修改文件并重算指纹（会被签名检测）

**测试文件：**
- [`test/example/encode_crate.sh`](test/example/encode_crate.sh)
- [`test/example/decode_crate.sh`](test/example/decode_crate.sh)
- [`test/example/hack_file.sh`](test/example/hack_file.sh)
- [`test/example/hack.py`](test/example/hack.py)

---

## 技术栈

- **bincode**: 二进制序列化
- **openssl**: PKCS7签名和SHA256
- **toml**: TOML解析
- **clap**: 命令行参数解析

**依赖配置：**
- [`Cargo.toml`](Cargo.toml)

---

## 设计特点

1. **自定义二进制格式**：紧凑且可扩展
2. **字符串表去重**：减少文件大小
3. **段索引**：支持随机访问
4. **多阶段编码**：先占位再签名，最后计算指纹
5. **分层验证**：指纹检查完整性，签名验证身份

---

## 代码索引

### 核心数据结构

| 结构体 | 文件位置 | 行号 |
|--------|---------|------|
| `PackageContext` | [`src/utils/context.rs`](src/utils/context.rs) | [24](src/utils/context.rs#L24) |
| `CratePackage` | [`src/utils/package/mod.rs`](src/utils/package/mod.rs) | [145](src/utils/package/mod.rs#L145) |
| `StringTable` | [`src/utils/context.rs`](src/utils/context.rs) | [273](src/utils/context.rs#L273) |
| `PackageInfo` | [`src/utils/context.rs`](src/utils/context.rs) | [115](src/utils/context.rs#L115) |
| `DepInfo` | [`src/utils/context.rs`](src/utils/context.rs) | [168](src/utils/context.rs#L168) |
| `SigInfo` | [`src/utils/context.rs`](src/utils/context.rs) | [382](src/utils/context.rs#L382) |

### 核心算法

| 功能 | 文件位置 | 行号 |
|------|---------|------|
| 编码流程 | [`src/utils/encode.rs`](src/utils/encode.rs) | [173](src/utils/encode.rs#L173) |
| 解码流程 | [`src/utils/decode.rs`](src/utils/decode.rs) | [154](src/utils/decode.rs#L154) |
| 签名计算 | [`src/utils/encode.rs`](src/utils/encode.rs) | [115](src/utils/encode.rs#L115) |
| 签名验证 | [`src/utils/decode.rs`](src/utils/decode.rs) | [129](src/utils/decode.rs#L129) |
| 指纹计算 | [`src/utils/encode.rs`](src/utils/encode.rs) | [137](src/utils/encode.rs#L137) |
| 指纹验证 | [`src/utils/decode.rs`](src/utils/decode.rs) | [124](src/utils/decode.rs#L124) |

### 入口点

| 功能 | 文件位置 | 行号 |
|------|---------|------|
| 命令行入口 | [`src/main.rs`](src/main.rs) | [38](src/main.rs#L38) |
| 打包逻辑 | [`src/pack.rs`](src/pack.rs) | [84](src/pack.rs#L84) |
| 解包逻辑 | [`src/unpack.rs`](src/unpack.rs) | [35](src/unpack.rs#L35) |

### 工具模块

| 功能 | 文件位置 |
|------|---------|
| PKCS7签名 | [`src/utils/pkcs.rs`](src/utils/pkcs.rs) |
| TOML解析 | [`src/utils/from_toml.rs`](src/utils/from_toml.rs) |
| 二进制序列化 | [`src/utils/package/gen_bincode.rs`](src/utils/package/gen_bincode.rs) |

---

## 快速导航

- [返回顶部](#crate-spec-项目概览)
- [项目结构](#项目结构)
- [核心模块](#核心模块分析)
- [执行流程](#执行流程)
- [代码索引](#代码索引)

---


## 设计上的问题
1. 若仅对 crate 计算摘要，计算 hash, 完全可以。

2. 若对完整文件计算 hash , 存在循环依赖。
   + index section 依赖于 sigStructure 的值
   + sigStructure 正确计算又依赖于  index section 的正确
   + 暂时解决办法：
      + 分步计算摘要，去除掉 index section 部分
      + 针对这部分来签名




## 实际构建过程
+ 设置 dep、pkg、strtable 信息
+ 构建 sigStuctures 各个部分的占位
+ 构建 sectionIndex 
+ 构建 strTable 
+ 构建 crateHeader 信息
-------------------------------------
问题根源：
+ 依据全部内容，更新sigStructures 部分
+ 更新索引的偏移数据
-------------------------------------
+ 计算出全文指纹


## todos
1. 性能优化
2. 解决签名的问题
3. 内部魔术部分考虑改为枚举实现
4. 内部设计了多个签名，实际实现仅一个签名，使用 pkcs.
5. 需要考虑底层数据布局
   + 填充、对齐的问题
   + 顺序的问题






