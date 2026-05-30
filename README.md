# Task-Oriented Scam Apps

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Android-lightgrey.svg" alt="Platform">
</p>

A toolkit for analyzing mobile **task-oriented scam applications**.

---

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Dataset](#dataset)
- [License](#license)
- [Contact](#contact)



## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install from source

```bash
# Clone the repository
git clone https://github.com/lighttt037/AppSamples.git
cd AppSamples

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Optional Dependencies

For PCAP parsing capabilities:
```bash
pip install scapy
```

For faster string matching:
```bash
pip install python-Levenshtein
```


## 📁 Project Structure

```
AppSamples/
├── src/                          # Source code
│   ├── __init__.py
│   ├── network/                  # Network evasion detection
│   │   ├── __init__.py           # Main entry point & CLI
│   │   ├── core.py               # Config and data classes
│   │   ├── parsers.py            # Traffic & MITM parsers
│   │   ├── detectors.py          # Detection implementations
│   │   └── find_missing_urls.py  # URL analysis
│   ├── detection/                # Static analysis tools
│   │   ├── certificate_analyzer.py
│   │   ├── permission_analyzer.py
│   │   ├── analysis_similarity.py
│   │   ├── searchurl.py
│   │   ├── extractwebview.py
│   │   ├── compareapk.py
│   │   └── ...
│   ├── collection/               # Data collection utilities
│   │   ├── duplicate_merge.py
│   │   ├── moguahashname.py
│   │   ├── moguatime.py
│   │   └── zhihuaspace.py
│   └── utils/                    # General utilities
│       ├── auto_jadx.py
│       ├── automitm.py
│       ├── autotcpdump.py
│       ├── pcap_parse.py
│       ├── ip2region.py
│       ├── emulatorcheck.py
│       └── ...
├── dataset/                      # Partial dataset
│   ├── metadata/
│   ├── samples/
│   └── README.md
├── prompts/                      # Classification prompts
│   ├── app_classification_prompt.md
│   └── README.md
├── examples/                     # Usage examples
├── requirements.txt
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## 🏷️ App Classification

We provide a classification taxonomy for task-oriented scam applications with **5 main categories** and **12 sub-categories**:

| Category | Description | Sub-categories |
|----------|-------------|----------------|
| **Investment & Finance** | Fake investment platforms | Securities & Futures, Cryptocurrency, Film & Art, Tech Startup |
| **Social Welfare & Policy** | Fake government programs | Government Funding, Healthcare & Pension, Refund Services |
| **Task & Commission** | Fake gig economy platforms | Shopping Rebates, Gig Platforms |
| **Fake Services** | Fake utility tools | Company Communication, Customer Support, Digital Wallets |
| **Others** | Unclear categories | - |

See [prompts/app_classification_prompt.md](prompts/app_classification_prompt.md) for the complete classification prompt and examples.

---

## 📊 Dataset

A partial dataset is included in this repository. The full dataset (~100GB, currently 2600+ samples and expanding) is available for academic research purposes.

### Request Full Dataset

📧 **Email**: [yc_guo@stu.hit.edu.cn](mailto:yc_guo@stu.hit.edu.cn)

Please include:
- Your name and affiliation
- Research purpose
- Agreement to our data usage policy

See [dataset/README.md](dataset/README.md) for more details.

---

## 💡 Usage Examples

See the [examples/](examples/) directory for detailed usage examples.

```bash
python examples/network_evasion_example.py
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Disclaimer**: This toolkit is provided for academic research and educational purposes only.

---

## 📬 Contact

- **Dataset Requests**: [yc_guo@stu.hit.edu.cn](mailto:yc_guo@stu.hit.edu.cn)

---

<p align="center">
  <i>Developed for academic research on mobile security</i>
</p>
