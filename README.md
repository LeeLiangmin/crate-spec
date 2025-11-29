# crate-spec

`crate-spec` is a new file format we've designed for Rust, characterized by its safety, reliability, and robustness. This brand-new file format allows Crate files to be mirrored and cached anywhere while providing end-to-end data integrity assurance and authentication capabilities.

We provide an application (`crate-spec`) to generate (encode) and decode new crate files with support for both local and network signing modes.

## Features

- **Dual Signing Modes**: Support for local PKCS7 signing and network PKI-based signing
- **Configuration File Support**: Use TOML configuration files for easier operation
- **Command Line Interface**: Flexible CLI for automation and scripting
- **End-to-End Integrity**: SHA256 fingerprint verification
- **Authentication**: PKCS7 digital signature verification
- **Modular Design**: Clean, maintainable, and extensible codebase

## Installation

```bash
git clone <repository-url>
cd crate-spec
cargo build --release
```

## Usage

### Mode Selection

crate-spec supports two signing modes:

- **Local Mode** (`--mode local`, default): Uses local certificates and private keys for signing
- **Network Mode** (`--mode net`): Uses PKI platform for network-based signing

### Encode (Generate .scrate file)

When using the encode (`-e`) option, the program will invoke the `cargo package` command to check and package the Rust project and perform additional operations such as signing it, ultimately generating a `.scrate` file.

#### Local Mode - Configuration File

Create a configuration file (default: `config/config.toml`):

```toml
[local.encode]
cert_path = "test/cert.pem"
root_ca_path = "test/root-ca.pem"
private_key_path = "test/key.pem"
output_path = "test/output/"
input_path = "../crate-spec"
```

Then run:

```bash
# Use default config file
crate-spec -e --config

# Use custom config file
crate-spec -e --config my_config.toml
```

#### Local Mode - Command Line Arguments

```bash
crate-spec -e --cli \
           -r test/root-ca.pem \
           -c test/cert.pem \
           -p test/key.pem \
           -o test/output \
           ../crate-spec
```

#### Network Mode

Create a configuration file:

```toml
[network.encode]
input_path = "../crate-spec"
output_path = "test/output/"

[net]
pki_base_url = "https://pki.example.com"
algo = "RSA"
flow = "default"
kms = "default"
key_pair_path = "config/keypair.bin"
retry_times = 3
retry_delay = 1000
```

Then run:

```bash
crate-spec -e --mode net --config
```

**Command Options:**
* `-e` (**must provide**): Enable encode mode
* `--mode <MODE>`: Signing mode (`local` or `net`, default: `local`)
* `--config [PATH]`: Use configuration file (default: `config/config.toml`)
* `--cli`: Use command line arguments (local mode only, mutually exclusive with `--config`)
* `-r <root-ca.pem>`: Root CA certificate file path (can specify multiple, CLI mode only)
* `-c <cert.pem>`: Publisher's certificate file path (CLI mode only)
* `-p <key.pem>`: Publisher's private key file path (CLI mode only)
* `-o <output_dir>`: Output directory path
* `<input>`: Input path (Rust project path for encoding)


### Decode (Verify and Extract .crate file)

When using the decode (`-d`) option, the program will decode the `.scrate` file, verifying its integrity and source. Once the verification passes, it will decode the file back into the original `.crate` file, which is used by Cargo, and also dump the package's metadata to `{crate_name}-{version}-metadata.txt`.

#### Local Mode - Configuration File

```toml
[local.decode]
root_ca_path = "test/root-ca.pem"
output_path = "test/output/"
input_path = "test/output/crate-spec-0.1.0.scrate"
```

```bash
crate-spec -d --config
```

#### Local Mode - Command Line Arguments

```bash
crate-spec -d --cli \
           -r test/root-ca.pem \
           -o test/output \
           test/output/crate-spec-0.1.0.scrate
```

#### Network Mode

```toml
[network.decode]
input_path = "test/output/crate-spec-0.1.0.scrate"
output_path = "test/output/"

[net]
pki_base_url = "https://pki.example.com"
retry_times = 3
retry_delay = 1000
```

```bash
crate-spec -d --mode net --config
```

**Command Options:**
* `-d` (**must provide**): Enable decode mode
* `--mode <MODE>`: Signing mode (`local` or `net`, default: `local`)
* `--config [PATH]`: Use configuration file (default: `config/config.toml`)
* `--cli`: Use command line arguments (local mode only)
* `-r <root-ca.pem>`: Root CA certificate file path (can specify multiple, CLI mode only)
* `-o <output_dir>`: Output directory path
* `<input>`: Input path (`.scrate` file path for decoding)

**Output Files:**
* `{name}-{version}.crate`: Original crate file
* `{name}-{version}-metadata.txt`: Package metadata (package info and dependencies)

## Examples

You can find example scripts in `test/example/`.

### 1. Encode Rust Project

**Using configuration file:**
```bash
# Create config/config.toml with [local.encode] section
crate-spec -e --config
```

**Using command line:**
```bash
crate-spec -e --cli \
           -r test/root-ca.pem \
           -c test/cert.pem \
           -p test/key.pem \
           -o test/output \
           ../crate-spec
```

This will encode the project to `crate-spec-0.1.0.scrate` file in `test/output`.

### 2. Decode `.scrate` File

**Using configuration file:**
```bash
# Create config/config.toml with [local.decode] section
crate-spec -d --config
```

**Using command line:**
```bash
crate-spec -d --cli \
           -r test/root-ca.pem \
           -o test/output \
           test/output/crate-spec-0.1.0.scrate
```

This will decode the `.scrate` file to original crate file `crate-spec-0.1.0.crate` and dump the metadata file `crate-spec-0.1.0-metadata.txt` in `test/output`.

### 3. Integrity Verification

#### File Transfer Error Detection

**a.** First, generate the `.scrate` file:
```bash
crate-spec -e --config
```

**b.** Simulate file transfer errors (modify some bytes):
```bash
sh test/example/hack_file.sh 0
```

**c.** Attempt to decode - integrity check will fail:
```bash
crate-spec -d --config
# Expected output: fingerprint verification error
```

#### Tampering Detection

**a.** Generate the `.scrate` file again:
```bash
crate-spec -e --config
```

**b.** Simulate malicious tampering (modify file and recalculate fingerprint):
```bash
sh test/example/hack_file.sh 1
```

**c.** Attempt to decode - signature verification will fail:
```bash
crate-spec -d --config
# Expected output: signature verification error
```

## Configuration File Format

### Local Mode Configuration

```toml
[local.encode]
cert_path = "test/cert.pem"
root_ca_path = "test/root-ca.pem"
private_key_path = "test/key.pem"
output_path = "test/output/"
input_path = "../crate-spec"

[local.decode]
root_ca_path = "test/root-ca.pem"
output_path = "test/output/"
input_path = "test/output/crate-spec-0.1.0.scrate"
```

### Network Mode Configuration

```toml
[network.encode]
input_path = "../crate-spec"
output_path = "test/output/"

[network.decode]
input_path = "test/output/crate-spec-0.1.0.scrate"
output_path = "test/output/"

[net]
pki_base_url = "https://pki.example.com"
algo = "RSA"
flow = "default"
kms = "default"
key_pair_path = "config/keypair.bin"
retry_times = 3
retry_delay = 1000
```

## Project Structure

```
crate-spec/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library entry
│   ├── pack.rs          # Packing logic
│   ├── unpack.rs        # Unpacking logic
│   ├── config.rs        # Configuration parsing
│   ├── config_ext.rs    # Configuration extensions
│   ├── network.rs       # Network signing support
│   ├── params.rs        # Parameter builder
│   ├── commands/        # Command execution modules
│   │   ├── encode.rs    # Encode commands
│   │   └── decode.rs    # Decode commands
│   └── utils/           # Utility modules
│       ├── file_ops.rs   # File operations
│       ├── context.rs    # Package context
│       ├── encode.rs     # Encoding implementation
│       ├── decode.rs     # Decoding implementation
│       └── ...
├── config/              # Configuration files
└── test/                # Test files and examples
```

## Security Features

- **Integrity Protection**: SHA256 fingerprint at file end
- **Authentication**: PKCS7 digital signature verification
- **Flexible Signing**: Support for multiple signatures and signature types
- **Network Signing**: Integration with PKI platforms for centralized key management

## Documentation

For more detailed documentation, see:
- [Project Outline](docs/outline.md) - Comprehensive project overview
- [Local Signing Guide](docs/本地签名版本使用说明.md) - Local mode usage guide
- [Network Signing Guide](docs/网络签名版本.md) - Network mode usage guide

## License

[Add your license information here]