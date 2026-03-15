# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Hash Analysis
# ═══════════════════════════════════════════════════════════════════════════════
# Comprehensive hash identification and analysis
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
#                              HASH SIGNATURES
# ───────────────────────────────────────────────────────────────────────────────

const HASH_SIGNATURES = Dict{Symbol, NamedTuple{(:length, :charset, :prefix, :description), 
                                                 Tuple{Union{Int, UnitRange{Int}}, Symbol, Union{String, Nothing}, String}}}(
    :md5 => (length=32, charset=:hex, prefix=nothing, description="MD5"),
    :md4 => (length=32, charset=:hex, prefix=nothing, description="MD4"),
    :md2 => (length=32, charset=:hex, prefix=nothing, description="MD2"),
    
    :sha1 => (length=40, charset=:hex, prefix=nothing, description="SHA-1"),
    :sha224 => (length=56, charset=:hex, prefix=nothing, description="SHA-224"),
    :sha256 => (length=64, charset=:hex, prefix=nothing, description="SHA-256"),
    :sha384 => (length=96, charset=:hex, prefix=nothing, description="SHA-384"),
    :sha512 => (length=128, charset=:hex, prefix=nothing, description="SHA-512"),
    
    :sha3_224 => (length=56, charset=:hex, prefix=nothing, description="SHA3-224"),
    :sha3_256 => (length=64, charset=:hex, prefix=nothing, description="SHA3-256"),
    :sha3_384 => (length=96, charset=:hex, prefix=nothing, description="SHA3-384"),
    :sha3_512 => (length=128, charset=:hex, prefix=nothing, description="SHA3-512"),
    
    :blake2b => (length=128, charset=:hex, prefix=nothing, description="BLAKE2b"),
    :blake2s => (length=64, charset=:hex, prefix=nothing, description="BLAKE2s"),
    :blake3 => (length=64, charset=:hex, prefix=nothing, description="BLAKE3"),
    
    :ripemd128 => (length=32, charset=:hex, prefix=nothing, description="RIPEMD-128"),
    :ripemd160 => (length=40, charset=:hex, prefix=nothing, description="RIPEMD-160"),
    :ripemd256 => (length=64, charset=:hex, prefix=nothing, description="RIPEMD-256"),
    :ripemd320 => (length=80, charset=:hex, prefix=nothing, description="RIPEMD-320"),
    
    :whirlpool => (length=128, charset=:hex, prefix=nothing, description="Whirlpool"),
    :tiger => (length=48, charset=:hex, prefix=nothing, description="Tiger"),
    :tiger2 => (length=48, charset=:hex, prefix=nothing, description="Tiger2"),
    
    :ntlm => (length=32, charset=:hex, prefix=nothing, description="NTLM"),
    :lm => (length=32, charset=:hex, prefix=nothing, description="LM"),
    
    :mysql323 => (length=16, charset=:hex, prefix=nothing, description="MySQL 3.23"),
    :mysql41 => (length=40, charset=:hex, prefix="*", description="MySQL 4.1+"),
    
    :bcrypt => (length=60, charset=:bcrypt, prefix="\$2", description="bcrypt"),
    :scrypt => (length=90:120, charset=:base64, prefix="\$scrypt", description="scrypt"),
    :argon2 => (length=80:120, charset=:base64, prefix="\$argon2", description="Argon2"),
    :pbkdf2 => (length=60:100, charset=:base64, prefix="\$pbkdf2", description="PBKDF2"),
    
    :phpass => (length=34, charset=:phpass, prefix="\$P\$", description="PHPass (WordPress, phpBB)"),
    :drupal7 => (length=55, charset=:drupal, prefix="\$S\$", description="Drupal 7"),
    
    :crc32 => (length=8, charset=:hex, prefix=nothing, description="CRC32"),
    :crc32b => (length=8, charset=:hex, prefix=nothing, description="CRC32B"),
    :adler32 => (length=8, charset=:hex, prefix=nothing, description="Adler-32"),
    
    :unix_md5 => (length=22:34, charset=:unix, prefix="\$1\$", description="Unix MD5 Crypt"),
    :unix_sha256 => (length=43:63, charset=:unix, prefix="\$5\$", description="Unix SHA-256 Crypt"),
    :unix_sha512 => (length=86:106, charset=:unix, prefix="\$6\$", description="Unix SHA-512 Crypt"),
    :unix_blowfish => (length=31:60, charset=:unix, prefix="\$2a\$", description="Unix Blowfish Crypt"),
)

# ───────────────────────────────────────────────────────────────────────────────
#                              CHARSET PATTERNS
# ───────────────────────────────────────────────────────────────────────────────

const CHARSET_PATTERNS = Dict{Symbol, Regex}(
    :hex => r"^[a-fA-F0-9]+$",
    :base64 => r"^[A-Za-z0-9+/=]+$",
    :base64url => r"^[A-Za-z0-9_-]+$",
    :bcrypt => r"^[A-Za-z0-9./]+$",
    :unix => r"^[A-Za-z0-9./]+$",
    :phpass => r"^[A-Za-z0-9./]+$",
    :drupal => r"^[A-Za-z0-9./]+$",
    :alphanumeric => r"^[A-Za-z0-9]+$",
)

# ───────────────────────────────────────────────────────────────────────────────
#                              HASH IDENTIFICATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    detect_charset(hash::AbstractString)

Detect the character set of a hash string.
"""
function detect_charset(hash::AbstractString)::Symbol
    for (charset, pattern) in CHARSET_PATTERNS
        if occursin(pattern, hash)
            return charset
        end
    end
    return :unknown
end

"""
    hash_identify(input::String; verbose::Bool = CONFIG.verbose)

Identify possible hash types from input string.

# Arguments
- `input::String`: Hash string to identify
- `verbose::Bool`: Show detailed output

# Returns
- `HashIdentification`: Identification result with possible types

# Example
```julia
result = hash_identify("5d41402abc4b2a76b9719d911017c592")
# => HashIdentification(["md5", "md4", "ntlm"], 0.95, ...)
```
"""
function hash_identify(input::String; verbose::Bool = CONFIG.verbose)::HashIdentification
    input = strip(input)
    len = length(input)
    charset = detect_charset(input)
    
    possible_types = Symbol[]
    confidence_scores = Dict{Symbol, Float64}()
    
    for (hash_type, sig) in HASH_SIGNATURES
        # Check length
        len_match = if isa(sig.length, Int)
            len == sig.length
        else
            len in sig.length
        end
        !len_match && continue
        
        # Check prefix
        if !isnothing(sig.prefix)
            !startswith(input, sig.prefix) && continue
        end
        
        # Check charset
        if charset != :unknown && sig.charset != :unknown
            charset_pattern = get(CHARSET_PATTERNS, sig.charset, nothing)
            if !isnothing(charset_pattern)
                if !occursin(charset_pattern, input)
                    continue
                end
            end
        end
        
        # Calculate confidence
        confidence = 0.5
        
        # Exact length match boosts confidence
        if isa(sig.length, Int)
            confidence += 0.2
        end
        
        # Prefix match boosts confidence
        if !isnothing(sig.prefix) && startswith(input, sig.prefix)
            confidence += 0.3
        end
        
        push!(possible_types, hash_type)
        confidence_scores[hash_type] = confidence
    end
    
    # Sort by confidence
    sort!(possible_types, by = t -> -get(confidence_scores, t, 0.0))
    
    # Calculate overall confidence
    overall_confidence = if length(possible_types) == 0
        0.0
    elseif length(possible_types) == 1
        get(confidence_scores, possible_types[1], 0.5)
    else
        get(confidence_scores, possible_types[1], 0.5) * 0.8
    end
    
    result = HashIdentification(input, possible_types, overall_confidence, len, charset)
    
    if verbose
        display_hash_identification(result)
    end
    
    return result
end

"""
    display_hash_identification(hi::HashIdentification)

Display formatted hash identification results.
"""
function display_hash_identification(hi::HashIdentification)
    println()
    println(themed("╔═══════════════════════════════════════════════════════╗", :primary))
    println(themed("║              HASH IDENTIFICATION                      ║", :primary))
    println(themed("╠═══════════════════════════════════════════════════════╣", :primary))
    
    # Display input hash (truncated if long)
    input_display = length(hi.input) > 50 ? hi.input[1:47] * "..." : hi.input
    println(themed("║", :primary), " Hash: ", themed(input_display, :cyan))
    println(themed("║", :primary), " Length: ", themed(string(hi.length), :yellow), " | Charset: ", themed(string(hi.charset), :yellow))
    println(themed("║", :primary), " Confidence: ", themed(@sprintf("%.1f%%", hi.confidence * 100), hi.confidence > 0.7 ? :green : :yellow))
    println(themed("╠═══════════════════════════════════════════════════════╣", :primary))
    
    if isempty(hi.possible_types)
        println(themed("║", :primary), themed(" No matching hash types found", :warning))
    else
        println(themed("║", :primary), themed(" Possible Types:", :success))
        for (i, htype) in enumerate(hi.possible_types[1:min(5, length(hi.possible_types))])
            sig = get(HASH_SIGNATURES, htype, nothing)
            desc = isnothing(sig) ? string(htype) : sig.description
            marker = i == 1 ? "→" : " "
            println(themed("║", :primary), "   $marker ", themed(desc, i == 1 ? :success : :dim), 
                    themed(" ($(htype))", :dim))
        end
    end
    
    println(themed("╚═══════════════════════════════════════════════════════╝", :primary))
end

# ───────────────────────────────────────────────────────────────────────────────
#                              HASH COMPUTATION
# ───────────────────────────────────────────────────────────────────────────────

"""
    compute_hash(data::Union{String, Vector{UInt8}}, algorithm::Symbol)

Compute hash of data using specified algorithm.

# Supported Algorithms
- :md5, :sha1, :sha224, :sha256, :sha384, :sha512
- :sha3_224, :sha3_256, :sha3_384, :sha3_512
"""
function compute_hash(data::Union{String, Vector{UInt8}}, algorithm::Symbol)::String
    bytes = isa(data, String) ? Vector{UInt8}(data) : data
    
    hash_result = if algorithm == :sha256
        sha256(bytes)
    elseif algorithm == :sha1
        sha1(bytes)
    elseif algorithm == :sha224
        sha224(bytes)
    elseif algorithm == :sha384
        sha384(bytes)
    elseif algorithm == :sha512
        sha512(bytes)
    elseif algorithm == :sha3_256
        sha3_256(bytes)
    elseif algorithm == :sha3_384
        sha3_384(bytes)
    elseif algorithm == :sha3_512
        sha3_512(bytes)
    else
        error("Unsupported hash algorithm: $algorithm")
    end
    
    return bytes2hex(hash_result)
end

"""
    compute_all_hashes(data::Union{String, Vector{UInt8}})

Compute multiple hashes of data.
"""
function compute_all_hashes(data::Union{String, Vector{UInt8}})::Dict{Symbol, String}
    bytes = isa(data, String) ? Vector{UInt8}(data) : data
    
    return Dict{Symbol, String}(
        :sha256 => bytes2hex(sha256(bytes)),
        :sha1 => bytes2hex(sha1(bytes)),
        :sha384 => bytes2hex(sha384(bytes)),
        :sha512 => bytes2hex(sha512(bytes)),
        :sha3_256 => bytes2hex(sha3_256(bytes)),
    )
end

"""
    file_hash(filepath::String, algorithm::Symbol = :sha256)

Compute hash of file contents.
"""
function file_hash(filepath::String, algorithm::Symbol = :sha256)::String
    isfile(filepath) || error("File not found: $filepath")
    
    data = read(filepath)
    return compute_hash(data, algorithm)
end

"""
    file_hashes(filepath::String)

Compute multiple hashes of file.
"""
function file_hashes(filepath::String)::Dict{Symbol, String}
    isfile(filepath) || error("File not found: $filepath")
    
    data = read(filepath)
    return compute_all_hashes(data)
end

# ───────────────────────────────────────────────────────────────────────────────
#                              HASH CRACKING UTILITIES
# ───────────────────────────────────────────────────────────────────────────────

"""
    generate_wordlist_hashes(wordlist::Vector{String}, algorithm::Symbol = :md5)

Generate hash lookup table from wordlist.
"""
function generate_wordlist_hashes(wordlist::Vector{String}, algorithm::Symbol = :sha256)::Dict{String, String}
    return Dict(compute_hash(word, algorithm) => word for word in wordlist)
end

"""
    rainbow_lookup(hash::String, table::Dict{String, String})

Look up hash in rainbow table.
"""
function rainbow_lookup(hash::String, table::Dict{String, String})::Union{String, Nothing}
    return get(table, lowercase(hash), nothing)
end

"""
    hash_compare(hash1::String, hash2::String)

Constant-time hash comparison (prevents timing attacks).
"""
function hash_compare(hash1::String, hash2::String)::Bool
    h1 = lowercase(hash1)
    h2 = lowercase(hash2)
    
    length(h1) != length(h2) && return false
    
    result = 0
    for i in eachindex(h1)
        result |= xor(UInt8(h1[i]), UInt8(h2[i]))
    end
    
    return result == 0
end

# ───────────────────────────────────────────────────────────────────────────────
#                              HMAC
# ───────────────────────────────────────────────────────────────────────────────

"""
    hmac_sha256(key::Union{String, Vector{UInt8}}, message::Union{String, Vector{UInt8}})

Compute HMAC-SHA256.
"""
function hmac_sha256(key::Union{String, Vector{UInt8}}, message::Union{String, Vector{UInt8}})::String
    k = isa(key, String) ? Vector{UInt8}(key) : key
    m = isa(message, String) ? Vector{UInt8}(message) : message
    
    return bytes2hex(hmac_sha256(k, m))
end
