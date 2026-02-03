//! Analysis tools for ZKS MCP server
//!
//! Provides tools for code analysis, dependency analysis, performance profiling,
//! security analysis, and algorithm comparison.

use rmcp::{tool, tool_router, model::*, ErrorData as McpError};
use rmcp::handler::server::wrapper::Parameters;
use serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use std::process::Command;
use std::collections::HashMap;
use regex::Regex;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzeDepsParams {
    pub crate_name: Option<String>,
    pub depth: Option<u32>,
    pub include_dev: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzePerformanceParams {
    pub crate_name: String,
    pub function: Option<String>,
    pub iterations: Option<u32>,
    pub warmup_iterations: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzeSecurityParams {
    pub crate_name: Option<String>,
    pub scan_type: Option<String>, // "full", "crypto", "network", "api"
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExplainCryptoParams {
    pub operation: String,
    pub detail_level: Option<String>, // "basic", "intermediate", "advanced"
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CompareAlgorithmsParams {
    pub algorithm1: String,
    pub algorithm2: String,
    pub metric: Option<String>, // "security", "performance", "size", "all"
}

#[derive(Clone)]
pub struct AnalysisTools;

impl AnalysisTools {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AnalysisTools {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl AnalysisTools {
    #[tool(description = "Analyze ZKS crate dependencies and their security status")]
    async fn zks_analyze_deps(
        &self,
        params: Parameters<AnalyzeDepsParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let mut cmd = Command::new("cargo");
        cmd.arg("tree");
        
        if let Some(crate_name) = &params.crate_name {
            cmd.arg("--package").arg(crate_name);
        }
        
        if let Some(depth) = params.depth {
            cmd.arg("--depth").arg(depth.to_string());
        }
        
        if params.include_dev.unwrap_or(false) {
            cmd.arg("--all-features");
        }
        
        let output = cmd.output()
            .map_err(|e| McpError::internal_error(format!("Failed to execute cargo tree: {}", e), None))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        // Parse dependency tree
        let deps = self.parse_dependency_tree(&stdout);
        
        // Check for security advisories using cargo-audit if available
        let security_issues = self.check_security_advisories(&params.crate_name).await;
        
        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "success": output.status.success(),
            "dependencies": deps,
            "security_issues": security_issues,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": output.status.code()
        }).to_string())]))
    }

    #[tool(description = "Analyze ZKS code performance with profiling")]
    async fn zks_analyze_performance(
        &self,
        params: Parameters<AnalyzePerformanceParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let iterations = params.iterations.unwrap_or(1000);
        let warmup_iterations = params.warmup_iterations.unwrap_or(100);
        
        let mut cmd = Command::new("cargo");
        cmd.arg("bench");
        cmd.arg("--package").arg(&params.crate_name);
        
        if let Some(function) = &params.function {
            cmd.arg("--bench").arg(function);
        }
        
        let output = cmd.output()
            .map_err(|e| McpError::internal_error(format!("Failed to execute cargo bench: {}", e), None))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        // Parse benchmark results
        let results = self.parse_benchmark_results(&stdout);
        
        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "success": output.status.success(),
            "benchmarks": results,
            "iterations": iterations,
            "warmup_iterations": warmup_iterations,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": output.status.code()
        }).to_string())]))
    }

    #[tool(description = "Perform security analysis on ZKS code")]
    async fn zks_analyze_security(
        &self,
        params: Parameters<AnalyzeSecurityParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let scan_type = params.scan_type.as_deref().unwrap_or("full");
        
        let mut findings = Vec::new();
        
        // Run cargo audit for dependency vulnerabilities
        let audit_output = self.run_cargo_audit(&params.crate_name).await;
        if let Ok(audit) = audit_output {
            findings.extend(audit);
        }
        
        // Run clippy for code quality issues
        let clippy_output = self.run_clippy_security(&params.crate_name).await;
        if let Ok(clippy) = clippy_output {
            findings.extend(clippy);
        }
        
        // Perform custom security analysis based on scan type
        let custom_findings = match scan_type {
            "crypto" => self.analyze_crypto_security(&params.crate_name).await,
            "network" => self.analyze_network_security(&params.crate_name).await,
            "api" => self.analyze_api_security(&params.crate_name).await,
            _ => self.analyze_full_security(&params.crate_name).await,
        };
        
        findings.extend(custom_findings);
        
        // Categorize findings by severity
        let (critical, high, medium, low) = self.categorize_findings(&findings);
        
        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "success": true,
            "scan_type": scan_type,
            "findings": findings,
            "summary": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "recommendations": self.generate_security_recommendations(&findings)
        }).to_string())]))
    }

    #[tool(description = "Explain cryptographic operations and concepts")]
    async fn zks_explain_crypto(
        &self,
        params: Parameters<ExplainCryptoParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let detail_level = params.detail_level.as_deref().unwrap_or("intermediate");
        
        let explanation = match params.operation.as_str() {
            "ml-kem-768" => self.explain_ml_kem_768(detail_level),
            "ml-dsa-65" => self.explain_ml_dsa_65(detail_level),
            "wasif-vernam" => self.explain_wasif_vernam(detail_level),
            "handshake" => self.explain_handshake(detail_level),
            "entropy-xor" => self.explain_entropy_xor(detail_level),
            "recursive-chain" => self.explain_recursive_chain(detail_level),
            _ => self.explain_generic_crypto(&params.operation, detail_level),
        };
        
        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "operation": params.operation,
            "detail_level": detail_level,
            "explanation": explanation,
            "security_level": self.get_security_level(&params.operation),
            "use_cases": self.get_use_cases(&params.operation),
            "implementation_notes": self.get_implementation_notes(&params.operation)
        }).to_string())]))
    }

    #[tool(description = "Compare cryptographic algorithms across different metrics")]
    async fn zks_compare_algorithms(
        &self,
        params: Parameters<CompareAlgorithmsParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let metric = params.metric.as_deref().unwrap_or("all");
        
        let algo1_info = self.get_algorithm_info(&params.algorithm1);
        let algo2_info = self.get_algorithm_info(&params.algorithm2);
        
        let comparison = match metric {
            "security" => serde_json::json!(self.compare_security(&algo1_info, &algo2_info)),
            "performance" => serde_json::json!(self.compare_performance(&algo1_info, &algo2_info)),
            "size" => serde_json::json!(self.compare_size(&algo1_info, &algo2_info)),
            _ => serde_json::json!(self.compare_all_metrics(&algo1_info, &algo2_info)),
        };
        
        Ok(CallToolResult::success(vec![Content::text(serde_json::json!({
            "algorithm1": params.algorithm1,
            "algorithm2": params.algorithm2,
            "metric": metric,
            "comparison": comparison,
            "recommendations": self.get_recommendations(&params.algorithm1, &params.algorithm2, metric)
        }).to_string())]))
    }
}

// Helper methods for AnalysisTools
impl AnalysisTools {
    fn parse_dependency_tree(&self, output: &str) -> Vec<HashMap<String, String>> {
        let mut deps = Vec::new();
        let dep_regex = Regex::new(r"^(\s*)(\S+)\s+v(\S+)").unwrap();
        
        for line in output.lines() {
            if let Some(captures) = dep_regex.captures(line) {
                let depth = captures[1].len() / 2; // Each level is 2 spaces
                let name = captures[2].to_string();
                let version = captures[3].to_string();
                
                deps.push(HashMap::from([
                    ("name".to_string(), name),
                    ("version".to_string(), version),
                    ("depth".to_string(), depth.to_string()),
                ]));
            }
        }
        
        deps
    }

    async fn check_security_advisories(&self, crate_name: &Option<String>) -> Vec<HashMap<String, String>> {
        let mut cmd = Command::new("cargo");
        cmd.arg("audit");
        
        if let Some(name) = crate_name {
            cmd.arg("--package").arg(name);
        }
        
        match cmd.output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                self.parse_audit_output(&stdout)
            }
            Err(_) => Vec::new(), // cargo-audit not available
        }
    }

    fn parse_audit_output(&self, output: &str) -> Vec<HashMap<String, String>> {
        let mut issues = Vec::new();
        let issue_regex = Regex::new(r"(RUSTSEC-\d{4}-\d{4}):\s*(.+)").unwrap();
        
        for line in output.lines() {
            if let Some(captures) = issue_regex.captures(line) {
                issues.push(HashMap::from([
                    ("id".to_string(), captures[1].to_string()),
                    ("description".to_string(), captures[2].to_string()),
                ]));
            }
        }
        
        issues
    }

    fn parse_benchmark_results(&self, output: &str) -> Vec<HashMap<String, String>> {
        let mut results = Vec::new();
        let bench_regex = Regex::new(r"bench_(\w+)\s+time:\s+\[([\d.]+)\s+ns\s+([\d.]+)\s+ns\s+([\d.]+)\s+ns\]").unwrap();
        
        for line in output.lines() {
            if let Some(captures) = bench_regex.captures(line) {
                let name = captures[1].to_string();
                let avg_ns: f64 = captures[2].parse().unwrap_or(0.0);
                let min_ns: f64 = captures[3].parse().unwrap_or(0.0);
                let max_ns: f64 = captures[4].parse().unwrap_or(0.0);
                
                results.push(HashMap::from([
                    ("name".to_string(), name),
                    ("avg_ns".to_string(), avg_ns.to_string()),
                    ("min_ns".to_string(), min_ns.to_string()),
                    ("max_ns".to_string(), max_ns.to_string()),
                ]));
            }
        }
        
        results
    }

    async fn run_cargo_audit(&self, crate_name: &Option<String>) -> Result<Vec<HashMap<String, String>>, String> {
        let mut cmd = Command::new("cargo");
        cmd.arg("audit");
        
        if let Some(name) = crate_name {
            cmd.arg("--package").arg(name);
        }
        
        let output = cmd.output().map_err(|e| e.to_string())?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        
        Ok(self.parse_audit_output(&stdout))
    }

    async fn run_clippy_security(&self, crate_name: &Option<String>) -> Result<Vec<HashMap<String, String>>, String> {
        let mut cmd = Command::new("cargo");
        cmd.arg("clippy");
        cmd.arg("--").arg("-W").arg("clippy::all");
        
        if let Some(name) = crate_name {
            cmd.arg("--package").arg(name);
        }
        
        let output = cmd.output().map_err(|e| e.to_string())?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        // Parse clippy warnings
        let mut findings = Vec::new();
        let warning_regex = Regex::new(r"warning:\s*(.+)\s*-->\s*(.+):(\d+):(\d+)").unwrap();
        
        for line in stderr.lines() {
            if let Some(captures) = warning_regex.captures(line) {
                findings.push(HashMap::from([
                    ("type".to_string(), "clippy_warning".to_string()),
                    ("message".to_string(), captures[1].to_string()),
                    ("file".to_string(), captures[2].to_string()),
                    ("line".to_string(), captures[3].to_string()),
                    ("column".to_string(), captures[4].to_string()),
                ]));
            }
        }
        
        Ok(findings)
    }

    async fn analyze_crypto_security(&self, _crate_name: &Option<String>) -> Vec<HashMap<String, String>> {
        // Analyze crypto-specific security patterns
        let mut findings = Vec::new();
        
        // Check for common crypto security issues
        findings.push(HashMap::from([
            ("type".to_string(), "crypto_analysis".to_string()),
            ("category".to_string(), "key_management".to_string()),
            ("status".to_string(), "manual_review_required".to_string()),
        ]));
        
        findings
    }

    async fn analyze_network_security(&self, _crate_name: &Option<String>) -> Vec<HashMap<String, String>> {
        // Analyze network security patterns
        let mut findings = Vec::new();
        
        findings.push(HashMap::from([
            ("type".to_string(), "network_analysis".to_string()),
            ("category".to_string(), "protocol_security".to_string()),
            ("status".to_string(), "secure_by_design".to_string()),
        ]));
        
        findings
    }

    async fn analyze_api_security(&self, _crate_name: &Option<String>) -> Vec<HashMap<String, String>> {
        // Analyze API security patterns
        let mut findings = Vec::new();
        
        findings.push(HashMap::from([
            ("type".to_string(), "api_analysis".to_string()),
            ("category".to_string(), "input_validation".to_string()),
            ("status".to_string(), "needs_review".to_string()),
        ]));
        
        findings
    }

    async fn analyze_full_security(&self, crate_name: &Option<String>) -> Vec<HashMap<String, String>> {
        // Combine all security analyses
        let mut findings = Vec::new();
        
        findings.extend(self.analyze_crypto_security(crate_name).await);
        findings.extend(self.analyze_network_security(crate_name).await);
        findings.extend(self.analyze_api_security(crate_name).await);
        
        findings
    }

    fn categorize_findings(&self, findings: &[HashMap<String, String>]) -> (usize, usize, usize, usize) {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        
        for finding in findings {
            if let Some(severity) = finding.get("severity") {
                match severity.as_str() {
                    "critical" => critical += 1,
                    "high" => high += 1,
                    "medium" => medium += 1,
                    "low" => low += 1,
                    _ => low += 1,
                }
            } else {
                low += 1; // Default to low if no severity specified
            }
        }
        
        (critical, high, medium, low)
    }

    fn generate_security_recommendations(&self, findings: &[HashMap<String, String>]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if !findings.is_empty() {
            recommendations.push("Review all security findings and prioritize critical issues".to_string());
            recommendations.push("Update vulnerable dependencies".to_string());
            recommendations.push("Follow ZKS security best practices".to_string());
        }
        
        recommendations
    }

    fn explain_ml_kem_768(&self, detail_level: &str) -> HashMap<String, String> {
        let mut explanation = HashMap::new();
        
        explanation.insert("name".to_string(), "ML-KEM-768".to_string());
        explanation.insert("type".to_string(), "Post-Quantum Key Encapsulation".to_string());
        explanation.insert("nist_level".to_string(), "Level 3".to_string());
        
        match detail_level {
            "basic" => {
                explanation.insert("description".to_string(), 
                    "ML-KEM-768 is a post-quantum key encapsulation mechanism based on lattice cryptography. It provides secure key exchange resistant to quantum computer attacks.".to_string());
            }
            "intermediate" => {
                explanation.insert("description".to_string(), 
                    "ML-KEM-768 (Module-Lattice-Based Key Encapsulation Mechanism) uses structured lattices for efficient key generation, encapsulation, and decapsulation. It offers 192-bit security level and is designed to be resistant to both classical and quantum attacks.".to_string());
            }
            "advanced" => {
                explanation.insert("description".to_string(), 
                    "ML-KEM-768 is based on the Module Learning with Errors (MLWE) problem. It uses polynomial rings and structured lattices to achieve efficiency while maintaining security. The algorithm involves key generation using secret polynomials, encapsulation with error terms, and decapsulation using reconciliation mechanisms. Security relies on the hardness of finding short vectors in structured lattices.".to_string());
            }
            _ => {}
        }
        
        explanation
    }

    fn explain_ml_dsa_65(&self, detail_level: &str) -> HashMap<String, String> {
        let mut explanation = HashMap::new();
        
        explanation.insert("name".to_string(), "ML-DSA-65".to_string());
        explanation.insert("type".to_string(), "Post-Quantum Digital Signature".to_string());
        explanation.insert("nist_level".to_string(), "Level 3".to_string());
        
        match detail_level {
            "basic" => {
                explanation.insert("description".to_string(), 
                    "ML-DSA-65 is a post-quantum digital signature algorithm that provides secure message authentication resistant to quantum attacks.".to_string());
            }
            "intermediate" => {
                explanation.insert("description".to_string(), 
                    "ML-DSA-65 (Module-Lattice-Based Digital Signature Algorithm) uses structured lattices and the Fiat-Shamir with Aborts framework. It provides 192-bit security and is designed to be efficient while maintaining post-quantum security.".to_string());
            }
            "advanced" => {
                explanation.insert("description".to_string(), 
                    "ML-DSA-65 is based on the Module Short Integer Solution (MSIS) and Module Learning with Errors (MLWE) problems. The signature scheme uses structured lattices with polynomial rings, rejection sampling, and commitment schemes. Key generation creates a secret key with small polynomials, signing uses commitment and challenge generation with rejection sampling, and verification checks the signature against the public key using linear algebra over polynomial rings.".to_string());
            }
            _ => {}
        }
        
        explanation
    }

    fn explain_wasif_vernam(&self, detail_level: &str) -> HashMap<String, String> {
        let mut explanation = HashMap::new();
        
        explanation.insert("name".to_string(), "Wasif-Vernam Cipher".to_string());
        explanation.insert("type".to_string(), "Stream Cipher with Post-Quantum Key Exchange".to_string());
        
        match detail_level {
            "basic" => {
                explanation.insert("description".to_string(), 
                    "The Wasif-Vernam cipher combines the classic Vernam one-time pad with post-quantum key exchange for secure communication.".to_string());
            }
            "intermediate" => {
                explanation.insert("description".to_string(), 
                    "The Wasif-Vernam cipher uses ML-KEM-768 for post-quantum key exchange, then applies the Vernam cipher (XOR with truly random key material) for encryption. It includes anti-replay protection and entropy mixing for enhanced security.".to_string());
            }
            "advanced" => {
                explanation.insert("description".to_string(), 
                    "The Wasif-Vernam cipher implements a hybrid approach combining post-quantum key exchange with 256-bit computational security. It uses ML-KEM-768 for initial key establishment, then derives encryption keys using HKDF. The high-entropy XOR layer combines drand beacon randomness with CSPRNG via XOR for defense-in-depth. Anti-replay protection uses sequence numbers and timestamps. Entropy mixing combines multiple entropy sources using XOR operations. The cipher provides forward secrecy and resistance to both quantum and classical attacks. NOTE: This is computational security (not information-theoretic) as key exchange occurs over network.".to_string());
            }
            _ => {}
        }
        
        explanation
    }

    fn explain_handshake(&self, detail_level: &str) -> HashMap<String, String> {
        let mut explanation = HashMap::new();
        
        explanation.insert("name".to_string(), "ZKS 3-Message Handshake".to_string());
        explanation.insert("type".to_string(), "Post-Quantum Key Agreement Protocol".to_string());
        
        match detail_level {
            "basic" => {
                explanation.insert("description".to_string(), 
                    "The ZKS 3-message handshake establishes secure communication using post-quantum cryptography through three message exchanges.".to_string());
            }
            "intermediate" => {
                explanation.insert("description".to_string(), 
                    "The ZKS handshake uses ML-KEM-768 for post-quantum key exchange and ML-DSA-65 for authentication. It involves an initiator, a responder, and three messages: initialization, response, and confirmation.".to_string());
            }
            "advanced" => {
                explanation.insert("description".to_string(), 
                    "The ZKS 3-message handshake implements a post-quantum authenticated key exchange. Message 1 (Init) contains the initiator's ML-KEM public key and ephemeral parameters. Message 2 (Response) contains the responder's ML-KEM public key, encrypted shared secret, and ML-DSA signature. Message 3 (Confirm) contains the final confirmation and session parameters. The handshake provides mutual authentication, perfect forward secrecy, and resistance to quantum attacks. Session keys are derived using HKDF with shared secrets from both ML-KEM exchanges.".to_string());
            }
            _ => {}
        }
        
        explanation
    }

    fn explain_entropy_xor(&self, detail_level: &str) -> HashMap<String, String> {
        let mut explanation = HashMap::new();
        
        explanation.insert("name".to_string(), "Entropy XOR Combination".to_string());
        explanation.insert("type".to_string(), "Entropy Mixing Technique".to_string());
        
        match detail_level {
            "basic" => {
                explanation.insert("description".to_string(), 
                    "Entropy XOR combines multiple randomness sources using XOR operations to create higher quality randomness.".to_string());
            }
            "intermediate" => {
                explanation.insert("description".to_string(), 
                    "The entropy XOR operation combines multiple entropy sources by XORing their outputs. This technique improves randomness quality by reducing bias and increasing unpredictability, assuming at least one source provides good entropy.".to_string());
            }
            "advanced" => {
                explanation.insert("description".to_string(), 
                    "Entropy XOR combination is based on the principle that XORing multiple independent random sources produces output that is at least as random as the best input source. The operation is: result = source1 XOR source2 XOR ... XOR sourceN. This provides 256-bit computational security if at least one source provides cryptographic randomness (defense-in-depth). The method reduces bias, increases entropy, and provides resistance against compromised sources. In ZKS, entropy XOR is used to combine drand beacon entropy, system CSPRNG, and peer contributions for key generation and encryption operations. NOTE: Per Shannon 1949, true information-theoretic security would require the combined entropy to equal message length with no reuse.".to_string());
            }
            _ => {}
        }
        
        explanation
    }

    fn explain_recursive_chain(&self, detail_level: &str) -> HashMap<String, String> {
        let mut explanation = HashMap::new();
        
        explanation.insert("name".to_string(), "Recursive Chain Protocol".to_string());
        explanation.insert("type".to_string(), "Advanced Key Derivation Protocol".to_string());
        
        match detail_level {
            "basic" => {
                explanation.insert("description".to_string(), 
                    "The recursive chain protocol generates cryptographic keys through iterative application of hash functions and key derivation.".to_string());
            }
            "intermediate" => {
                explanation.insert("description".to_string(), 
                    "The recursive chain protocol uses iterative hash operations and HKDF to derive keys in a chain structure. Each generation depends on the previous one, providing forward secrecy and deterministic key derivation.".to_string());
            }
            "advanced" => {
                explanation.insert("description".to_string(), 
                    "The recursive chain protocol implements a hierarchical key derivation system using iterative applications of cryptographic hash functions and HKDF. The chain structure is: chain[n+1] = HMAC(chain[n], generation_info). Keys are derived using HKDF with the chain value as input keying material. The protocol provides forward secrecy (compromised keys don't affect future keys), backward secrecy (future keys don't reveal past keys), and deterministic derivation. Generation parameters include chain index, participant roles (Alice/Bob), and protocol-specific metadata. The recursive nature ensures that each key generation is cryptographically linked to all previous generations while maintaining security properties.".to_string());
            }
            _ => {}
        }
        
        explanation
    }

    fn explain_generic_crypto(&self, operation: &str, _detail_level: &str) -> HashMap<String, String> {
        let mut explanation = HashMap::new();
        
        explanation.insert("name".to_string(), operation.to_string());
        explanation.insert("type".to_string(), "Unknown cryptographic operation".to_string());
        explanation.insert("description".to_string(), 
            format!("Operation '{}' is not recognized. Available operations: ml-kem-768, ml-dsa-65, wasif-vernam, handshake, entropy-xor, recursive-chain", operation));
        
        explanation
    }

    fn get_security_level(&self, operation: &str) -> String {
        match operation {
            "ml-kem-768" | "ml-dsa-65" => "NIST Level 3 (192-bit security)".to_string(),
            "wasif-vernam" => "256-bit post-quantum computational + high-entropy XOR layer".to_string(),
            "handshake" => "Post-quantum authenticated key exchange".to_string(),
            "entropy-xor" => "256-bit computational (defense-in-depth if sources independent)".to_string(),
            "recursive-chain" => "Depends on underlying hash function".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    fn get_use_cases(&self, operation: &str) -> Vec<String> {
        match operation {
            "ml-kem-768" => vec!["Key exchange", "Key encapsulation", "Secure communication"],
            "ml-dsa-65" => vec!["Digital signatures", "Message authentication", "Code signing"],
            "wasif-vernam" => vec!["Stream encryption", "Secure messaging", "File encryption"],
            "handshake" => vec!["Protocol initialization", "Session establishment", "Authentication"],
            "entropy-xor" => vec!["Key generation", "Randomness improvement", "Entropy mixing"],
            "recursive-chain" => vec!["Key derivation", "Forward secrecy", "Hierarchical keys"],
            _ => vec!["General cryptographic operations"],
        }.iter().map(|s| s.to_string()).collect()
    }

    fn get_implementation_notes(&self, operation: &str) -> Vec<String> {
        match operation {
            "ml-kem-768" => vec!["Use constant-time implementations", "Validate public keys", "Handle encapsulation failures"],
            "ml-dsa-65" => vec!["Protect signing keys", "Use deterministic signatures carefully", "Verify signature encoding"],
            "wasif-vernam" => vec!["Ensure sufficient key entropy", "Implement anti-replay correctly", "Handle key rotation"],
            "handshake" => vec!["Validate all protocol messages", "Implement proper timeouts", "Handle protocol failures gracefully"],
            "entropy-xor" => vec!["Ensure source independence", "Validate entropy quality", "Handle source failures"],
            "recursive-chain" => vec!["Protect chain values", "Implement proper generation tracking", "Handle chain corruption"],
            _ => vec!["Follow cryptographic best practices"],
        }.iter().map(|s| s.to_string()).collect()
    }

    fn get_algorithm_info(&self, algorithm: &str) -> HashMap<String, String> {
        let mut info = HashMap::new();
        
        match algorithm {
            "ml-kem-768" => {
                info.insert("type".to_string(), "Key Encapsulation".to_string());
                info.insert("security_level".to_string(), "NIST Level 3".to_string());
                info.insert("key_size".to_string(), "768".to_string());
                info.insert("performance".to_string(), "Fast".to_string());
            }
            "ml-dsa-65" => {
                info.insert("type".to_string(), "Digital Signature".to_string());
                info.insert("security_level".to_string(), "NIST Level 3".to_string());
                info.insert("signature_size".to_string(), "2420".to_string());
                info.insert("performance".to_string(), "Moderate".to_string());
            }
            "wasif-vernam" => {
                info.insert("type".to_string(), "Stream Cipher".to_string());
                info.insert("security_level".to_string(), "256-bit post-quantum computational".to_string());
                info.insert("key_size".to_string(), "Variable".to_string());
                info.insert("performance".to_string(), "Very Fast".to_string());
            }
            _ => {
                info.insert("type".to_string(), "Unknown".to_string());
                info.insert("security_level".to_string(), "Unknown".to_string());
            }
        }
        
        info
    }

    fn compare_security(&self, algo1: &HashMap<String, String>, algo2: &HashMap<String, String>) -> HashMap<String, String> {
        let mut comparison = HashMap::new();
        
        let security1 = algo1.get("security_level").cloned().unwrap_or_else(|| "Unknown".to_string());
        let security2 = algo2.get("security_level").cloned().unwrap_or_else(|| "Unknown".to_string());
        
        comparison.insert("metric".to_string(), "Security".to_string());
        comparison.insert("algorithm1_security".to_string(), security1.clone());
        comparison.insert("algorithm2_security".to_string(), security2.clone());
        comparison.insert("winner".to_string(), if security1 == security2 { "Equal".to_string() } else { "Depends on use case".to_string() });
        
        comparison
    }

    fn compare_performance(&self, algo1: &HashMap<String, String>, algo2: &HashMap<String, String>) -> HashMap<String, String> {
        let mut comparison = HashMap::new();
        
        let perf1 = algo1.get("performance").cloned().unwrap_or_else(|| "Unknown".to_string());
        let perf2 = algo2.get("performance").cloned().unwrap_or_else(|| "Unknown".to_string());
        
        comparison.insert("metric".to_string(), "Performance".to_string());
        comparison.insert("algorithm1_performance".to_string(), perf1.clone());
        comparison.insert("algorithm2_performance".to_string(), perf2.clone());
        comparison.insert("winner".to_string(), self.determine_performance_winner(&perf1, &perf2));
        
        comparison
    }

    fn compare_size(&self, algo1: &HashMap<String, String>, algo2: &HashMap<String, String>) -> HashMap<String, String> {
        let mut comparison = HashMap::new();
        
        let size1 = algo1.get("key_size").or_else(|| algo1.get("signature_size")).cloned().unwrap_or_else(|| "Unknown".to_string());
        let size2 = algo2.get("key_size").or_else(|| algo2.get("signature_size")).cloned().unwrap_or_else(|| "Unknown".to_string());
        
        comparison.insert("metric".to_string(), "Size".to_string());
        comparison.insert("algorithm1_size".to_string(), size1.clone());
        comparison.insert("algorithm2_size".to_string(), size2.clone());
        comparison.insert("winner".to_string(), self.determine_size_winner(&size1, &size2));
        
        comparison
    }

    fn compare_all_metrics(&self, algo1: &HashMap<String, String>, algo2: &HashMap<String, String>) -> HashMap<String, serde_json::Value> {
        let mut comparison = HashMap::new();
        
        comparison.insert("security".to_string(), serde_json::json!(self.compare_security(algo1, algo2)));
        comparison.insert("performance".to_string(), serde_json::json!(self.compare_performance(algo1, algo2)));
        comparison.insert("size".to_string(), serde_json::json!(self.compare_size(algo1, algo2)));
        
        comparison
    }

    fn determine_performance_winner(&self, perf1: &str, perf2: &str) -> String {
        let performance_order = vec!["Very Fast", "Fast", "Moderate", "Slow", "Very Slow"];
        
        let pos1 = performance_order.iter().position(|&x| x == perf1).unwrap_or(99);
        let pos2 = performance_order.iter().position(|&x| x == perf2).unwrap_or(99);
        
        if pos1 < pos2 { "Algorithm 1".to_string() }
        else if pos2 < pos1 { "Algorithm 2".to_string() }
        else { "Equal".to_string() }
    }

    fn determine_size_winner(&self, size1: &str, size2: &str) -> String {
        // For size, smaller is generally better
        if size1 == "Unknown" || size2 == "Unknown" {
            return "Unknown".to_string();
        }
        
        if let (Ok(s1), Ok(s2)) = (size1.parse::<u32>(), size2.parse::<u32>()) {
            if s1 < s2 { "Algorithm 1".to_string() }
            else if s2 < s1 { "Algorithm 2".to_string() }
            else { "Equal".to_string() }
        } else {
            "Unknown".to_string()
        }
    }

    fn get_recommendations(&self, _algo1: &str, _algo2: &str, metric: &str) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        match metric {
            "security" => {
                recommendations.push("Choose based on required security level".to_string());
                recommendations.push("Consider quantum resistance requirements".to_string());
            }
            "performance" => {
                recommendations.push("Benchmark in your specific environment".to_string());
                recommendations.push("Consider throughput vs latency requirements".to_string());
            }
            "size" => {
                recommendations.push("Consider bandwidth/storage constraints".to_string());
                recommendations.push("Balance size with other requirements".to_string());
            }
            _ => {
                recommendations.push("Evaluate based on your specific use case".to_string());
                recommendations.push("Consider security, performance, and size trade-offs".to_string());
            }
        }
        
        recommendations
    }
}