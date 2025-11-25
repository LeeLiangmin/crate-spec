# 配置文件使用说明

本项目支持通过配置文件来设置命令行参数，简化重复操作。

## 配置文件格式

配置文件使用 TOML 格式，支持 `[encode]` 和 `[decode]` 两个部分：

```toml
[encode]
cert_path = "test/cert.pem"
root_ca_path = "test/root-ca.pem"
private_key_path = "test/key.pem"
output_path = "test/output/"
input_path = "../crate-spec"

[decode]
root_ca_path = "test/root-ca.pem"
output_path = "test/output/"
input_path = "test/output/crate-spec-0.1.0.scrate"
```

## 使用方法

### 1. 使用默认配置文件

将配置保存为 `config/config.toml`，程序会自动加载：

```bash
# 编码模式
cargo run -- -e -f

# 解码模式 
cargo run -- -d  -f 
```

### 2. 指定配置文件

使用 `-c` 参数指定配置文件路径：

```bash
# 编码模式
cargo run -- -e -f my_config.toml

# 解码模式
cargo run -- -d -f my_config.toml
```

### 3. 命令行参数优先

命令行参数会覆盖配置文件中的对应设置：

```bash
# 使用配置文件，但覆盖输出路径
cargo run -- -e -f config.toml -o /tmp/output/

# 使用配置文件，但覆盖输入路径
cargo run -- -d -f config.toml test/output/other.scrate
```

### 4. 纯命令行模式

如果不提供配置文件，程序会使用命令行参数（需要提供所有必需参数）：

```bash
# 编码
cargo run -- -e -c test/cert.pem -r test/root-ca.pem -p test/key.pem -o test/output/ ../crate-spec

# 解码
cargo run -- -d -r test/root-ca.pem -o test/output/ test/output/crate-spec-0.1.0.scrate
```

## 配置项说明

### [encode] 部分

| 配置项 | 说明 | 对应命令行参数 |
|--------|------|---------------|
| `cert_path` | 证书文件路径 | `-c` |
| `root_ca_path` | 根CA证书路径 | `-r` |
| `private_key_path` | 私钥文件路径 | `-p` |
| `output_path` | 输出目录路径 | `-o` |
| `input_path` | 输入文件路径 | 位置参数 |

### [decode] 部分

| 配置项 | 说明 | 对应命令行参数 |
|--------|------|---------------|
| `root_ca_path` | 根CA证书路径 | `-r` |
| `output_path` | 输出目录路径 | `-o` |
| `input_path` | 输入文件路径 | 位置参数 |

## 优先级

配置优先级从高到低：

1. **命令行参数** - 最高优先级
2. **配置文件** - 中等优先级
3. **默认值** - 如果都不提供则报错

## 示例

### 示例 1: 使用默认配置进行编码

```bash
# 1. 创建 config/config.toml
cat > config/config.toml << EOF
[encode]
cert_path = "test/cert.pem"
root_ca_path = "test/root-ca.pem"
private_key_path = "test/key.pem"
output_path = "test/output/"
input_path = "../crate-spec"
EOF

# 2. 运行编码
cargo run -- -e
```

### 示例 2: 使用自定义配置文件

```bash
# 1. 创建自定义配置文件
cat > my_encode.toml << EOF
[encode]
cert_path = "/path/to/cert.pem"
root_ca_path = "/path/to/root-ca.pem"
private_key_path = "/path/to/key.pem"
output_path = "/tmp/output/"
input_path = "/path/to/crate"
EOF

# 2. 使用自定义配置文件
cargo run -- -e -c my_encode.toml
```

### 示例 3: 配置文件 + 命令行参数混合

```bash
# 使用配置文件，但覆盖输入路径
cargo run -- -e -c config/config.toml ../other-crate
```

## 注意事项
1. 配置文件路径可以是相对路径或绝对路径
2. 如果配置文件不存在，程序会报错（除非使用默认配置文件，不存在时使用命令行参数）
3. 配置文件中的路径可以使用相对路径（相对于当前工作目录）
4. 命令行参数会完全覆盖配置文件中的对应项

