# ZKS Protocol - Remote Swarm Deployment Script
# Usage: ./deploy_swarm.ps1

# 1. Configuration
$User = "root"
$KeyPath = "$HOME/.ssh/id_rsa" # Verify this path
$RemoteDir = "/opt/zks"

# VPS List (REPLACE WITH REAL IBS)
# Format: @{ IP="x.x.x.x"; Role="relay" }
$Nodes = @(
    @{ IP="192.168.1.10"; Role="authority" },
    @{ IP="192.168.1.11"; Role="relay" },
    @{ IP="192.168.1.12"; Role="relay" },
    @{ IP="192.168.1.13"; Role="relay" },
    @{ IP="192.168.1.14"; Role="relay" },
    @{ IP="192.168.1.15"; Role="relay" },
    @{ IP="192.168.1.16"; Role="relay" },
    @{ IP="192.168.1.17"; Role="relay" }
)

# 2. Local Compilation
Write-Host "🚀 Compiling zks-admin for Linux..." -ForegroundColor Cyan
# Ensure we strictly build for Linux (musl preferred for portability, but gnu is standard)
# Note: This requires 'cross' or a linux toolchain on windows. 
# Fallback: We'll upload source and compile on VPS if cross-compilation isn't set up.
# For now, let's assume we upload source for maximum compatibility.

$SourcePath = "D:\ZKS Protocol_Research\ZKS Protocol\crates"
$ConfigPath = "D:\ZKS Protocol_Research\ZKS Protocol\Cargo.toml"

# 3. Deployment Loop
ForEach ($Node in $Nodes) {
    $IP = $Node.IP
    $Role = $Node.Role
    
    Write-Host "Connecting to $Role ($IP)..." -ForegroundColor Yellow
    
    # A. Setup Remote Dir & Dependencies
    ssh -i $KeyPath $User@$IP "apt-get update && apt-get install -y build-essential cargo git"
    ssh -i $KeyPath $User@$IP "mkdir -p $RemoteDir/crates"

    # B. Upload Source (Rsync would be better, but SCP is standard on Windows)
    # We upload the whole workspace to ensure dependencies resolve
    Write-Host "📦 Uploading source code..."
    scp -i $KeyPath -r $SourcePath $User@$IP:$RemoteDir
    scp -i $KeyPath $ConfigPath $User@$IP:$RemoteDir

    # C. Compile & Run
    Write-Host "⚙️  Compiling and Starting Node..."
    $Command = "cd $RemoteDir && cargo run --release --example zks_admin -- start --role $Role --bind 0.0.0.0:9443"
    
    # Run in background (nohup)
    ssh -i $KeyPath $User@$IP "nohup $Command > zks.log 2>&1 &"
}

Write-Host "✅ Deployment initiated on all nodes." -ForegroundColor Green
