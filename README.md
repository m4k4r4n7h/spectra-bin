# Spectra-Bin: Multi-Language Binary Reverse Engineering Engine

Spectra-Bin is a static binary analysis and reverse engineering engine written in **C**, **C++**, and **Python**. It inspects executable binaries from raw byte distributions and container headers down to disassembled machine instructions and operating system execution lifecycles.

## Architecture

1. **C Layer (`src/binprobe.c`)**: Zero-copy `mmap` file ingestion, Shannon entropy calculation, magic-byte fingerprinting, and 64-bit ELF segment/permission analysis.
2. **C++ Layer (`src/revcore.cpp`)**: Capstone-powered machine code disassembler and instruction semantic classifier (`syscall`, control-flow branches, stack operations, and hardware probes).
3. **Python Layer (`spectra/` & `main.py`)**: Native `ctypes` bridge to `libspectra.so`, multi-format container unpacker (ELF & PE), behavioral symbol clustering, and OS kernel execution lifecycle modeling.

## Prerequisites

* **Linux / macOS** with `gcc`, `g++`, and `make`
* **Capstone Disassembly Framework** development headers (`libcapstone-dev` on Debian/Ubuntu, `capstone` on Homebrew)
* **Python 3.8+**

## Quick Start

```bash
# Install system and Python dependencies
sudo apt-get install -y build-essential libcapstone-dev
pip install -r requirements.txt

# Compile the C/C++ shared library (build/libspectra.so)
make

# Analyze any binary on your system
python3 main.py /bin/ls
