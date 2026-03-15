"""
    Spectra.jl - Security Protocol Engine for Cyber Threat Response & Analysis

High-performance security framework written in Julia.
Blazing fast • Type-safe • Memory-efficient • Cryptographically secure

Author: bad-antics
Repository: https://github.com/bad-antics/spectra
"""
module SpectraSec

# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA SECURITY FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════════

using Dates
using Printf
using Random
using SHA
using Sockets
using Statistics
using TOML
using UUIDs

# Version info
const VERSION = v"0.1.0"
const AUTHOR = "bad-antics"
const REPO = "https://github.com/bad-antics/spectra"

# ───────────────────────────────────────────────────────────────────────────────
#                                   EXPORTS
# ───────────────────────────────────────────────────────────────────────────────

export 
    # Core
    init, configure, status, banner,
    # Types
    Target, ScanResult, ThreatLevel, PortState, SpectraConfig,
    Threat, HashIdentification, EntropyResult, ThreatScore, AggregateScore,
    # Enum values
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
    OPEN, CLOSED, FILTERED, UNKNOWN,
    # Scanning
    scan, quick_scan, full_scan, stealth_scan,
    # Analysis
    analyze, score, classify, report,
    scan_for_patterns, calculate_threat_score, aggregate_scores, assess_risk,
    # Crypto
    hash_identify, entropy_analyze, random_bytes, compute_hash, compute_all_hashes,
    # Network
    port_scan, service_detect, banner_grab,
    parse_ipv4_header, parse_tcp_header, parse_udp_header,
    # Recon
    dns_enum, subdomain_scan, whois_lookup,
    # Utilities
    colorize, table, progress

# ───────────────────────────────────────────────────────────────────────────────
#                                    CORE TYPES
# ───────────────────────────────────────────────────────────────────────────────

"""
    PortState

Enumeration of possible port states.
"""
@enum PortState begin
    OPEN
    CLOSED
    FILTERED
    UNKNOWN
end

"""
    ThreatLevel

Severity classification for threats.
"""
@enum ThreatLevel begin
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0
end

"""
    Target

Represents a scan target with all relevant metadata.
"""
struct Target
    host::String
    ports::Vector{Int}
    protocol::Symbol
    timeout::Float64
    
    function Target(host::String; 
                    ports::AbstractVector{<:Integer} = 1:1000,
                    protocol::Symbol = :tcp,
                    timeout::Float64 = 5.0)
        new(host, collect(ports), protocol, timeout)
    end
end

"""
    ScanResult

Holds the result of a port scan.
"""
struct ScanResult
    target::Target
    port::Int
    state::PortState
    service::Union{String, Nothing}
    banner::Union{String, Nothing}
    timestamp::DateTime
    latency::Float64
end

"""
    SpectraConfig

Global configuration for Spectra.
"""
mutable struct SpectraConfig
    theme::Symbol
    verbose::Bool
    parallel::Bool
    max_threads::Int
    timeout::Float64
    rate_limit::Int
    colors::Bool
    unicode::Bool
    nullsec_integration::Bool
end

# Global configuration instance
const CONFIG = SpectraConfig(
    :hacker,    # theme
    true,       # verbose
    true,       # parallel
    8,          # max_threads
    5.0,        # timeout
    1000,       # rate_limit
    true,       # colors
    true,       # unicode
    true        # nullsec_integration
)

# ───────────────────────────────────────────────────────────────────────────────
#                                   COLORS
# ───────────────────────────────────────────────────────────────────────────────

const COLORS = Dict(
    :reset    => "\e[0m",
    :bold     => "\e[1m",
    :dim      => "\e[2m",
    :red      => "\e[91m",
    :green    => "\e[92m",
    :yellow   => "\e[93m",
    :blue     => "\e[94m",
    :magenta  => "\e[95m",
    :cyan     => "\e[96m",
    :white    => "\e[97m",
    :bg_red   => "\e[41m",
    :bg_green => "\e[42m",
)

"""
    colorize(text, color)

Apply ANSI color to text.
"""
function colorize(text::String, color::Symbol)
    CONFIG.colors ? "$(COLORS[color])$(text)$(COLORS[:reset])" : text
end

# ───────────────────────────────────────────────────────────────────────────────
#                                   BANNER
# ───────────────────────────────────────────────────────────────────────────────

const BANNER = """
$(COLORS[:cyan])
███████╗██████╗ ███████╗ ██████╗████████╗██████╗  █████╗ 
██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗
███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝███████║
╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══██║
███████║██║     ███████╗╚██████╗   ██║   ██║  ██║██║  ██║
╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
$(COLORS[:reset])$(COLORS[:dim])
   Security Protocol Engine for Cyber Threat Response & Analysis
   v$(VERSION) | github.com/bad-antics$(COLORS[:reset])
"""

"""
    banner()

Display the Spectra banner.
"""
function banner()
    println(BANNER)
end

# ───────────────────────────────────────────────────────────────────────────────
#                               INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    init(; kwargs...)

Initialize Spectra with configuration options.

# Arguments
- `theme::Symbol`: Display theme (:hacker, :minimal, :colorful)
- `verbose::Bool`: Enable verbose output
- `parallel::Bool`: Enable parallel processing
- `colors::Bool`: Enable colored output
"""
function init(; 
              theme::Symbol = :hacker,
              verbose::Bool = true,
              parallel::Bool = true,
              colors::Bool = true)
    
    CONFIG.theme = theme
    CONFIG.verbose = verbose
    CONFIG.parallel = parallel
    CONFIG.colors = colors
    
    verbose && banner()
    verbose && println(colorize("[*] Spectra initialized", :green))
    verbose && println(colorize("    Theme: $theme | Parallel: $parallel | Colors: $colors", :dim))
    
    return nothing
end

"""
    configure(config_path::String)

Load configuration from TOML file.
"""
function configure(config_path::String)
    if isfile(config_path)
        cfg = TOML.parsefile(config_path)
        
        if haskey(cfg, "general")
            g = cfg["general"]
            CONFIG.theme = Symbol(get(g, "theme", "hacker"))
            CONFIG.verbose = get(g, "verbose", true)
            CONFIG.parallel = get(g, "parallel", true)
            CONFIG.max_threads = get(g, "max_threads", 8)
        end
        
        if haskey(cfg, "network")
            n = cfg["network"]
            CONFIG.timeout = get(n, "timeout", 5.0)
            CONFIG.rate_limit = get(n, "rate_limit", 1000)
        end
        
        if haskey(cfg, "output")
            o = cfg["output"]
            CONFIG.colors = get(o, "colors", true)
            CONFIG.unicode = get(o, "unicode", true)
        end
        
        CONFIG.verbose && println(colorize("[+] Configuration loaded from $config_path", :green))
    else
        @warn "Configuration file not found: $config_path"
    end
end

"""
    status()

Display current Spectra status.
"""
function status()
    println(colorize("┌─────────────────────────────────────┐", :cyan))
    println(colorize("│         SPECTRA STATUS              │", :cyan))
    println(colorize("├─────────────────────────────────────┤", :cyan))
    println(colorize("│ ", :cyan), "Version:  ", colorize("$VERSION", :green), colorize("                    │", :cyan))
    println(colorize("│ ", :cyan), "Theme:    ", colorize("$(CONFIG.theme)", :yellow), colorize("                   │", :cyan))
    println(colorize("│ ", :cyan), "Parallel: ", colorize("$(CONFIG.parallel)", :yellow), colorize("                    │", :cyan))
    println(colorize("│ ", :cyan), "Threads:  ", colorize("$(Threads.nthreads())", :yellow), colorize("                        │", :cyan))
    println(colorize("│ ", :cyan), "NullSec:  ", colorize("$(CONFIG.nullsec_integration)", :green), colorize("                    │", :cyan))
    println(colorize("└─────────────────────────────────────┘", :cyan))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              INCLUDE MODULES
# ───────────────────────────────────────────────────────────────────────────────

include("core/Types.jl")
include("core/Config.jl")
include("core/Engine.jl")
include("core/Display.jl")

include("crypto/Hashes.jl")
include("crypto/Entropy.jl")
include("crypto/Ciphers.jl")

include("network/Packets.jl")
include("network/Sockets.jl")
include("network/Protocols.jl")

include("modules/Scanner.jl")
include("modules/Recon.jl")
include("modules/Fuzzer.jl")
include("modules/Forensics.jl")

include("analysis/Patterns.jl")
include("analysis/Anomaly.jl")
include("analysis/Scoring.jl")

include("integrations/NullSec.jl")

# ───────────────────────────────────────────────────────────────────────────────
#                                MODULE END
# ───────────────────────────────────────────────────────────────────────────────

end # module SpectraSec
