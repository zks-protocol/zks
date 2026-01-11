# 🔐 ZKS Protocol - AWS Open Source Credits Application

> **Complete Application Guide for AWS Open Source Credits Program**

---

## 📋 Application Form - FILLED DATA

Below is the filled application data for ZKS Protocol. Copy these values into the Excel form.

---

### ⚠️ FIELDS YOU MUST FILL (Personal/Account Info)

| Field | Value | Notes |
|-------|-------|-------|
| **First Name** | `[YOUR FIRST NAME]` | Your legal first name |
| **Last Name** | `[YOUR LAST NAME]` | Your legal last name |
| **Job Title** | `[YOUR TITLE]` | e.g., "Founder", "Lead Developer", "Project Maintainer" |
| **AWS Account Email** | `[YOUR AWS EMAIL]` | Email associated with your AWS account |
| **AWS Account ID** | `[YOUR 12-DIGIT ACCOUNT ID]` | Find at: https://console.aws.amazon.com/billing/home?#/account |
| **Country/Region** | `[YOUR COUNTRY]` | e.g., "Bangladesh", "United States" |

---

### ✅ PRE-FILLED FIELDS (Project Info)

| Field | Value |
|-------|-------|
| **Open source project name** | `ZKS Protocol` |
| **URL for project repository** | `https://github.com/zks-protocol/zks` |
| **Project license** | `https://github.com/zks-protocol/zks/blob/main/LICENSE` |
| **Whether the project is state owned?** | `No` |

---

### 📝 DETAILED RESPONSES

#### 1. What are you looking to accomplish with the AWS credits for Open Source Projects?

```
ZKS Protocol requires AWS infrastructure to:

1. **CI/CD Pipeline & Testing**: Run continuous integration tests across multiple platforms (Linux, macOS, Windows, WebAssembly) for our Rust-based post-quantum cryptography crates. This includes cryptographic test vectors, fuzzing, and security audits.

2. **Relay Network Infrastructure**: Deploy and maintain ZKS swarm relay nodes on EC2 instances across multiple AWS regions to enable our anonymous onion-routing network (zks:// protocol). This provides true decentralized infrastructure for privacy-preserving communications.

3. **drand Beacon Integration**: Host entropy collection services that integrate with drand (distributed randomness beacon) for our information-theoretic security layer, which requires consistent uptime and global distribution.

4. **Documentation & Package Distribution**: Host documentation sites, WASM package distribution, and API endpoints using S3, CloudFront, and Lambda for the developer community.

5. **Performance Benchmarking**: Conduct comprehensive performance benchmarks of ML-KEM-768 and ML-DSA-65 post-quantum algorithms across various EC2 instance types to optimize for different deployment scenarios.
```

---

#### 2. Please provide the URL to your pricing estimate summary.

#### 2. Please provide the URL to your pricing estimate summary.

**Pricing Estimate URL:** [Insert your generated AWS Calculator Link Here]

**Breakdown of Services (Annual Estimate: ~$4,905):**

| Service | Configuration | Monthly Cost | Annual Cost |
|---------|---------------|--------------|-------------|
| **EC2 (Relay Nodes)** | 8x t3.medium (Distributed nodes) | ~$308 | ~$3,700 |
| **EC2 (CI/CD)** | 1x c5.xlarge (200 hrs/mo) | ~$39 | ~$468 |
| **CloudFront** | 500GB Outbound + 1M Requests | ~$43.50 | ~$522 |
| **S3 Storage** | 100GB Storage + 100GB Transfer | ~$14.68 | ~$176 |
| **Lambda** | 1M Requests (API) | ~$1.87 | ~$22 |
| **ECR** | 10GB Container Storage | ~$1.00 | ~$12 |
| **TOTAL** | | **~$408** | **~$4,900** |

---

#### 3. Requested amount (in USD)

```
$5,000
```

**Justification:**
This amount covers the essential 12-month infrastructure costs for the ZKS Protocol. The primary cost is running a cluster of 8 relay nodes for our anonymous `zks://` network ($4,903 est). We have rounded to $5,000 to cover minor currency fluctuation or data transfer spikes. The budget also supports critical CI/CD compilation workloads, documentation hosting via CloudFront, and necessary API services.

---

#### 4. Project Description (3-4 sentences)

```
ZKS Protocol is an ongoing research initiative at BRAC University developing the world's first post-quantum secure networking protocol with built-in anonymous routing. Providing both zk:// (direct) and zks:// (onion-routed) connections, it is built entirely in Rust with 100% safe code and implements NIST-standardized ML-KEM-768/ML-DSA-65 algorithms. The protocol allows developers to build quantum-resistant encrypted messengers, anonymous APIs, and privacy-preserving AI applications. ZKS Protocol is sponsored by Cloudflare Project Alexandria and published on crates.io, serving the global developer community.
```

---

## 📧 Submission Instructions

1. **Fill the Excel Form**: Copy the values above into `AWS+Open+Source+Credits+Application+Form.xlsx`

2. **Create AWS Pricing Estimate**: 
   - Go to https://calculator.aws/
   - Add the services listed above
   - Save and copy the share link
   - Paste into the form

3. **Email the Application**:
   - **To**: `awsopensourcecredits@amazon.com`
   - **Subject**: `AWS Open Source Credits Application - ZKS Protocol`
   - **Attachment**: Completed Excel form
   - **Body**: Brief introduction (see template below)

---

## ✉️ Email Template

```
Subject: AWS Open Source Credits Application - ZKS Protocol

Dear AWS Open Source Team,

I am submitting an application for the AWS Cloud Credits for Open Source Program on behalf of ZKS Protocol.

ZKS Protocol (https://github.com/zks-protocol/zks) is an ongoing security research initiative at BRAC University focusing on post-quantum secure networking infrastructure. The project provides end-to-end encrypted and anonymous communications using NIST-standardized algorithms (ML-KEM/ML-DSA) and is licensed under AGPL-3.0.

We are requesting $4,900 in credits to support:
- A decentralized relay network of 8 high-availability nodes
- CI/CD infrastructure for cross-platform Rust compilation
- Global documentation hosting and package distribution

Please find the completed application form attached.

Thank you for supporting our research.

Best regards,
[Your Name]
Project Creator & Researcher, ZKS Protocol
BRAC University
```

---

## ✅ Eligibility Checklist

| Requirement | ZKS Protocol Status |
|-------------|---------------------|
| OSI-approved license | ✅ AGPL-3.0 |
| Not VC-funded | ✅ Independent project |
| Active maintenance | ✅ Regular commits, published on crates.io |
| Not state-owned | ✅ No |
| Technical complement to AWS | ✅ Uses EC2, S3, CloudFront, Lambda |
| Multi-entity maintainers | ✅ Open for contributions |

---

## 📅 Timeline

- **Applications reviewed**: Monthly
- **Credit validity**: 1 year from issue date
- **Note**: Credits not issued in December (plan ahead!)

---

> **After Submission**: You will receive an email notification if approved, followed by a welcome email once credits are applied to your account.
