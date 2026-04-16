# 🌈 SPECTRA

<div align="center">

```
# Spectra — Spectral Analysis & Security Framework

         Security Protocol Engine for Cyber Threat Response & Analysis
```

[![Julia](https://img.shields.io/badge/Julia-1.10+-9558B2?style=for-the-badge&logo=julia&logoColor=white)](https://julialang.org/)
[![NullSec](https://img.shields.io/badge/NullSec-Integrated-00ff41?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/bad-antics)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)

**The first high-performance security framework written entirely in Julia**

*Blazing fast • Type-safe • Memory-efficient • Cryptographically secure*

</div>

---

## 🎯 What is Spectra?

**Spectra** is a revolutionary security framework that leverages Julia's scientific computing power for cybersecurity applications. Unlike traditional tools, Spectra uses Julia's JIT compilation to achieve **C-level performance** while maintaining the expressiveness of high-level code.

### Why Julia for Security?

- **🚀 Performance**: JIT-compiled to native code, approaching C/Rust speeds
- **🧮 Numerical Computing**: Built-in support for cryptographic mathematics
- **🔬 Scientific Analysis**: Statistical analysis of network patterns and anomalies
- **📊 Parallel Processing**: Native multi-threading and distributed computing
- **🛡️ Type Safety**: Strong type system catches errors at compile time
- **📦 Composable**: Multiple dispatch enables elegant, extensible APIs

---

## ✨ Features

### Core Capabilities

| Module | Description | Status |
|--------|-------------|--------|
| **Crypto** | Modern cryptographic primitives, hash analysis, entropy testing | ✅ |
| **Network** | Packet analysis, port scanning, service fingerprinting | ✅ |
| **Analysis** | Pattern recognition, anomaly detection, threat scoring | ✅ |
| **Recon** | DNS enumeration, subdomain discovery, OSINT gathering | ✅ |
| **Forensics** | File analysis, memory inspection, artifact extraction | ✅ |
| **Fuzzing** | Protocol fuzzing, input mutation, crash detection | ✅ |

### Unique Innovations

- **🌊 Waveform Analysis**: Analyze network traffic as signal waveforms
- **🧬 Entropy Fingerprinting**: Identify malware by entropy signatures
- **🔮 Predictive Threat Modeling**: ML-powered threat prediction
- **⚡ Parallel Scanning**: Distributed scanning across cores/nodes
- **🎨 Visual Attack Mapping**: ASCII art attack flow visualization
- **🔗 NullSec Integration**: Seamless integration with NullSec Linux

---

## 📦 Installation

### Requirements

- Julia 1.10 or higher
- Linux/macOS/Windows

### Quick Install

```julia
using Pkg
Pkg.add(url="https://github.com/bad-antics/spectra")
```

### From Source

```bash
git clone https://github.com/bad-antics/spectra.git
cd spectra
julia --project=. -e 'using Pkg; Pkg.instantiate()'
```

### NullSec Integration

```bash
# On NullSec Linux, Spectra is pre-installed
nullsec spectra
```

---

## 🚀 Quick Start

### Basic Usage

```julia
using Spectra

# Initialize with your style
Spectra.init(theme=:hacker, verbose=true)

# Quick port scan
results = Spectra.scan("192.168.1.0/24", ports=1:1000)

# Analyze results
Spectra.analyze(results) |> Spectra.report
```

### Network Reconnaissance

```julia
using Spectra.Network

# Async port scanning with service detection
@async_scan begin
    targets = ["192.168.1.1", "192.168.1.2"]
    ports = [22, 80, 443, 8080]
    
    for target in targets
        scan(target, ports, 
             timeout=2.0,
             service_detection=true,
             banner_grab=true)
    end
end
```

### Cryptographic Analysis

```julia
using Spectra.Crypto

# Entropy analysis
entropy = analyze_entropy("suspicious_file.bin")
println("Shannon Entropy: $(entropy.shannon)")
println("Compression Ratio: $(entropy.compression_ratio)")
println("Classification: $(entropy.classification)")

# Hash identification
identify_hash("5d41402abc4b2a76b9719d911017c592")
# => HashType(:MD5, confidence=0.98)
```

### Threat Analysis

```julia
using Spectra.Analysis

# Analyze network capture
threats = analyze_pcap("capture.pcap")

# Score and prioritize
for threat in sort(threats, by=:severity, rev=true)
    println("$(threat.name): $(threat.score)/100")
    println("  └─ $(threat.recommendation)")
end
```

---

## 🏗️ Architecture

```
spectra/
├── src/
│   ├── Spectra.jl           # Main module
│   ├── core/
│   │   ├── Types.jl         # Core type definitions
│   │   ├── Config.jl        # Configuration management
│   │   ├── Engine.jl        # Processing engine
│   │   └── Display.jl       # Beautiful output formatting
│   ├── modules/
│   │   ├── Scanner.jl       # Network scanning
│   │   ├── Recon.jl         # Reconnaissance
│   │   ├── Fuzzer.jl        # Fuzzing engine
│   │   └── Forensics.jl     # Digital forensics
│   ├── crypto/
│   │   ├── Hashes.jl        # Hash functions & analysis
│   │   ├── Ciphers.jl       # Encryption/decryption
│   │   └── Entropy.jl       # Entropy analysis
│   ├── network/
│   │   ├── Packets.jl       # Packet crafting
│   │   ├── Sockets.jl       # Raw socket operations
│   │   └── Protocols.jl     # Protocol implementations
│   ├── analysis/
│   │   ├── Patterns.jl      # Pattern recognition
│   │   ├── Anomaly.jl       # Anomaly detection
│   │   └── Scoring.jl       # Threat scoring
│   └── integrations/
│       └── NullSec.jl       # NullSec Linux integration
├── test/                    # Comprehensive tests
├── docs/                    # Documentation
└── examples/                # Usage examples
```

---

## 🎨 Beautiful Output

Spectra produces stunning terminal output:

```
┌─────────────────────────────────────────────────────────────┐
│  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗   │
│  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗  │
│  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║  │
│  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║  │
│  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║  │
│  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  │
├─────────────────────────────────────────────────────────────┤
│  Target: 192.168.1.1                                        │
│  Ports Scanned: 1000 | Open: 5 | Filtered: 23 | Closed: 972 │
│  Scan Time: 2.34s | Rate: 427 ports/sec                     │
├─────────────────────────────────────────────────────────────┤
│  PORT     STATE    SERVICE         VERSION                  │
│  ────     ─────    ───────         ───────                  │
│  22/tcp   open     ssh             OpenSSH 8.9p1            │
│  80/tcp   open     http            nginx/1.24.0             │
│  443/tcp  open     https           nginx/1.24.0             │
│  3306/tcp open     mysql           MySQL 8.0.35             │
│  8080/tcp open     http-proxy      Squid 5.7                │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Configuration

```julia
# ~/.spectra/config.toml
[general]
theme = "hacker"        # hacker, minimal, colorful
verbose = true
parallel = true
max_threads = 8

[network]
timeout = 5.0
retries = 3
rate_limit = 1000       # packets per second

[output]
format = "table"        # table, json, csv
colors = true
unicode = true

[nullsec]
integration = true
log_path = "/var/log/nullsec"
```

---

## 🤝 NullSec Integration

Spectra is designed to work seamlessly with NullSec Linux:

```bash
# Launch from NullSec menu
nullsec spectra

# Use in NullSec modules
source /opt/nullsec/spectra/bridge.sh
spectra_scan $TARGET
```

```julia
# In Julia, access NullSec features
using Spectra.Integrations.NullSec

# Read NullSec target
target = get_nullsec_target()

# Log to NullSec
log_to_nullsec(:vulnerability, "SQL Injection found", severity=:high)

# Use NullSec's Shodan integration
shodan_results = nullsec_shodan_search("apache")
```

---

## 📚 Examples

### Full Reconnaissance Pipeline

```julia
using Spectra

# Define target
target = Target("example.com")

# Run full recon pipeline
results = @pipeline target begin
    dns_enum          # DNS enumeration
    subdomain_scan    # Subdomain discovery
    port_scan         # Port scanning
    service_detect    # Service detection
    vuln_check        # Vulnerability check
    report            # Generate report
end

# Export results
export(results, "report.html", format=:html)
```

### Custom Module

```julia
# Create your own Spectra module
module MyModule

using Spectra.Core

@spectra_module "my_scanner" begin
    description = "My custom scanner"
    author = "bad-antics"
    
    function run(target::Target; options...)
        # Your scanning logic here
        results = []
        
        for port in get(options, :ports, 1:1000)
            if is_open(target.host, port)
                push!(results, PortResult(port, :open))
            end
        end
        
        return results
    end
end

end # module
```

---

## 🧪 Testing

```bash
# Run all tests
julia --project=. test/runtests.jl

# Run specific test suite
julia --project=. -e 'using Pkg; Pkg.test(test_args=["crypto"])'
```

---

## 📖 Documentation

Full documentation available at: [docs/](docs/)

- [Getting Started Guide](docs/getting-started.md)
- [API Reference](docs/api.md)
- [Module Development](docs/modules.md)
- [NullSec Integration](docs/nullsec.md)

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📜 License

MIT License - See [LICENSE](LICENSE)

---

## 🔗 Links

- **Repository**: https://github.com/bad-antics/spectra
- **NullSec**: https://github.com/bad-antics/nullsec
- **Author**: https://github.com/bad-antics

---

<div align="center">

**Built with 💚 by [bad-antics](https://github.com/bad-antics)**

*Part of the NullSec Security Ecosystem*

</div>
