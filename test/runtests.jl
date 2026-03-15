# ═══════════════════════════════════════════════════════════════════════════════
#                              SPECTRA - Test Suite
# ═══════════════════════════════════════════════════════════════════════════════

using Test
using Dates

# Include the main module
include("../src/Spectra.jl")
using .Spectra

@testset "Spectra Core Tests" begin
    
    @testset "Types" begin
        # Test Target creation with keyword arguments
        target = Target("example.com"; ports=[443], protocol=:tcp)
        @test target.host == "example.com"
        @test target.ports == [443]
        @test target.protocol == :tcp
        @test target.timeout == 5.0

        # Test default Target
        default_target = Target("10.0.0.1")
        @test default_target.host == "10.0.0.1"
        @test length(default_target.ports) == 1000
        @test default_target.protocol == :tcp
        
        # Test ThreatLevel ordering
        @test Int(CRITICAL) > Int(HIGH)
        @test Int(HIGH) > Int(MEDIUM)
        @test Int(MEDIUM) > Int(LOW)
        @test Int(LOW) > Int(INFO)

        # Test PortState enum
        @test OPEN isa PortState
        @test CLOSED isa PortState
        @test FILTERED isa PortState
    end
    
    @testset "Configuration" begin
        # Test global CONFIG exists and is a SpectraConfig
        @test Spectra.CONFIG isa SpectraConfig
        @test Spectra.CONFIG.verbose isa Bool
        @test Spectra.CONFIG.max_threads >= 1
        @test Spectra.CONFIG.timeout > 0.0
        
        # Test init with verbose=false (to suppress banner output)
        init(verbose=false)
        @test Spectra.CONFIG.verbose == false

        # Restore verbose
        Spectra.CONFIG.verbose = true

        # Test set_config!
        Spectra.set_config!("general", "verbose", false)
        @test Spectra.CONFIG.verbose == false
        Spectra.set_config!("general", "verbose", true)
    end
    
    @testset "Crypto - Hash Identification" begin
        # Test MD5 detection (suppress verbose output)
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = hash_identify(md5_hash, verbose=false)
        @test result isa HashIdentification
        @test length(result.possible_types) > 0
        @test :md5 in result.possible_types
        @test result.length == 32
        @test result.confidence > 0.0
        
        # Test SHA256 detection
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = hash_identify(sha256_hash, verbose=false)
        @test :sha256 in result.possible_types
        @test result.length == 64
    end
    
    @testset "Crypto - Entropy" begin
        # Test low entropy (suppress verbose output)
        low_entropy_data = UInt8[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        result = entropy_analyze(low_entropy_data, verbose=false)
        @test result isa EntropyResult
        @test result.entropy < 1.0
        @test !result.is_encrypted
        @test !result.is_random
        @test result.classification == :very_low
        
        # Test high entropy
        high_entropy_data = collect(UInt8, 0:255)
        result = entropy_analyze(high_entropy_data, verbose=false)
        @test result.entropy > 7.0
        @test result.is_random
        @test result.ratio > 0.9
    end
    
    @testset "Network - Packet Structures" begin
        # Test IPv4 header parsing
        ipv4_data = UInt8[
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01,
            0xc0, 0xa8, 0x01, 0x02
        ]
        header = parse_ipv4_header(ipv4_data)
        @test header !== nothing
        @test header.version == 4
        @test header.protocol == 6  # TCP
        @test header.ttl == 64  # 0x40

        # Test TCP header parsing  
        tcp_data = UInt8[
            0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00
        ]
        tcp_header = parse_tcp_header(tcp_data)
        @test tcp_header !== nothing
        @test tcp_header.src_port == 80
        @test tcp_header.dst_port == 443
    end
    
    @testset "Analysis - Patterns" begin
        # Test SQL injection detection
        sqli_test = "SELECT * FROM users WHERE id='1' OR '1'='1'"
        results = scan_for_patterns(sqli_test)
        @test length(results) > 0
        @test any(m -> m.pattern.category == :injection, results)
        
        # Test XSS detection
        xss_test = "<script>alert('XSS')</script>"
        results = scan_for_patterns(xss_test)
        @test length(results) > 0
        @test any(m -> m.pattern.name == "Cross-Site Scripting", results)

        # Test clean input (no patterns)
        clean_test = "Hello world, this is normal text."
        results = scan_for_patterns(clean_test)
        @test length(results) == 0
    end
    
    @testset "Scoring" begin
        # Test threat scoring
        threat = Threat(
            HIGH,
            :injection,
            "SQL Injection",
            "Found SQL injection vulnerability"
        )
        score = calculate_threat_score(threat)
        @test score isa ThreatScore
        @test score.base_score == 7.5  # HIGH = 7.5
        @test score.adjusted_score > 0
        @test score.severity == HIGH
        
        # Test aggregate scoring
        threats = [
            Threat(MEDIUM, :misc, "Test 1", "Description 1"),
            Threat(HIGH, :injection, "Test 2", "Description 2"),
        ]
        agg = aggregate_scores(threats)
        @test agg isa AggregateScore
        @test agg.threat_count == 2
        @test agg.high_count == 1
        @test agg.medium_count == 1
        @test agg.grade isa Symbol

        # Test risk assessment
        assessment = assess_risk("example.com", threats)
        @test !isempty(assessment.recommendations)
        @test !isempty(assessment.executive_summary)
    end

    @testset "Crypto - Hash Computation" begin
        # Test SHA256 computation
        hash = compute_hash("hello", :sha256)
        @test length(hash) == 64
        @test hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

        # Test multiple hashes
        hashes = compute_all_hashes("test")
        @test haskey(hashes, :sha256)
        @test haskey(hashes, :sha1)
        @test haskey(hashes, :sha512)
    end

    @testset "Crypto - Random" begin
        # Test random byte generation
        bytes = random_bytes(32)
        @test length(bytes) == 32
        @test bytes isa Vector{UInt8}

        # Different calls should produce different results
        bytes2 = random_bytes(32)
        @test bytes != bytes2
    end
end

println("\n✓ All Spectra tests passed!")
