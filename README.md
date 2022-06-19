# Awesome Binary Analysis

---

- [Description](#description)
- [Labels Indexes](#labels-indexes)
    - [By Type](#by-type)
    - [By Purpose](#by-purpose)
- [Resources](#resources)
- [Contribution](#contribution)

---

## Description

A **list of helpful binary analysis tools and research materials** can be found in this repository.

All resources are alphabetically organized and labeled, making it simple to locate them simply searching one item from the index on the entire page (with `CTRL+F`). The ones not having a link attached are present in the `documents/` folder.

## Labels Indexes

### By Type

- ![Type: awesome](https://img.shields.io/badge/Type-awesome-lightgrey)
- ![Type: book](https://img.shields.io/badge/Type-book-lightgrey)
- ![Type: brief](https://img.shields.io/badge/Type-brief-lightgrey)
- ![Type: code%20snippets](https://img.shields.io/badge/Type-code%20snippets-lightgrey)
- ![Type: dataset](https://img.shields.io/badge/Type-dataset-lightgrey)
- ![Type: enumeration](https://img.shields.io/badge/Type-enumeration-lightgrey)
- ![Type: library](https://img.shields.io/badge/Type-library-lightgrey)
- ![Type: paper](https://img.shields.io/badge/Type-paper-lightgrey)
- ![Type: publication](https://img.shields.io/badge/Type-publication-lightgrey)
- ![Type: study%20case](https://img.shields.io/badge/Type-study%20case-lightgrey)
- ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
- ![Type: website](https://img.shields.io/badge/Type-website-lightgrey)
- ![Type: workshop](https://img.shields.io/badge/Type-workshop-lightgrey)

### By Purpose

- ![Purpose: attack%20surface%20approximation](https://img.shields.io/badge/Purpose-attack%20surface%20approximation-blue)
- ![Purpose: binary%20analysis](https://img.shields.io/badge/Purpose-binary%20analysis-blue)
- ![Purpose: binary%20rewriting](https://img.shields.io/badge/Purpose-binary%20rewriting-blue)
- ![Purpose: control--flow%20analysis](https://img.shields.io/badge/Purpose-control--flow%20analysis-blue)
- ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue)
- ![Purpose: data--dependency%20analysis](https://img.shields.io/badge/Purpose-data--dependency%20analysis-blue)
- ![Purpose: decompilation](https://img.shields.io/badge/Purpose-decompilation-blue)
- ![Purpose: disassembly](https://img.shields.io/badge/Purpose-disassembly-blue)
- ![Purpose: dynamic%20analysis](https://img.shields.io/badge/Purpose-dynamic%20analysis-blue)
- ![Purpose: emulator](https://img.shields.io/badge/Purpose-emulator-blue)
- ![Purpose: executables%20parsing](https://img.shields.io/badge/Purpose-executables%20parsing-blue)
- ![Purpose: exploit%20generation](https://img.shields.io/badge/Purpose-exploit%20generation-blue)
- ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue)
- ![Purpose: lifting](https://img.shields.io/badge/Purpose-lifting-blue)
- ![Purpose: loading](https://img.shields.io/badge/Purpose-loading-blue)
- ![Purpose: research](https://img.shields.io/badge/Purpose-research-blue)
- ![Purpose: sandbox](https://img.shields.io/badge/Purpose-sandbox-blue)
- ![Purpose: static%20analysis](https://img.shields.io/badge/Purpose-static%20analysis-blue)
- ![Purpose: symbolic%20execution](https://img.shields.io/badge/Purpose-symbolic%20execution-blue)
- ![Purpose: taint%20analysis](https://img.shields.io/badge/Purpose-taint%20analysis-blue)
- ![Purpose: taint--analysis](https://img.shields.io/badge/Purpose-taint--analysis-blue)
- ![Purpose: value--set%20analysis](https://img.shields.io/badge/Purpose-value--set%20analysis-blue)
- ![Purpose: vulnerability%20detection](https://img.shields.io/badge/Purpose-vulnerability%20detection-blue)

## Resources

- **(State of) The Art of War: Offensive Techniques in Binary Analysis**
    - Description: angr's presentation
    - Type: ![Type: paper](https://img.shields.io/badge/Type-paper-lightgrey)
    - Purpose: ![Purpose: exploit%20generation](https://img.shields.io/badge/Purpose-exploit%20generation-blue)
- **A Honeybug for Automated Cyber Reasoning Systems**
    - Description: presentation of Rubeus and honeybugs as in Cyber Grand Challenge
    - Type: ![Type: publication](https://img.shields.io/badge/Type-publication-lightgrey)
    - Purpose: ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue)
- **[Address Sanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)**
    - Description: a memory error detector for C/C++
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: vulnerability%20detection](https://img.shields.io/badge/Purpose-vulnerability%20detection-blue)
- **[AFL](https://github.com/google/AFL)**
    - Description: (Now unmaintained) mutational fuzzer
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[AFL++](https://aflplus.plus/)**
    - Description: fuzzer continuing AFL with additional features
    - Type: ![Type: library](https://img.shields.io/badge/Type-library-lightgrey) ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[AFLgo](https://github.com/aflgo/aflgo)**
    - Description: AFL extension for directed fuzzing
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[AFLNet](https://github.com/aflnet/aflnet)**
    - Description: AFL extension for fuzzing network fuzzer
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[AFLSmart](https://github.com/aflsmart/aflsmart)**
    - Description: AFL extension that transforms it to a smart fuzzer by considering the input structure
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[angr](https://angr.io/)**
    - Description: Python 3 library for static and dynamic binary analysis
    - Type: ![Type: library](https://img.shields.io/badge/Type-library-lightgrey)
    - Purpose: ![Purpose: control--flow%20analysis](https://img.shields.io/badge/Purpose-control--flow%20analysis-blue) ![Purpose: data--dependency%20analysis](https://img.shields.io/badge/Purpose-data--dependency%20analysis-blue) ![Purpose: decompilation](https://img.shields.io/badge/Purpose-decompilation-blue) ![Purpose: disassembly](https://img.shields.io/badge/Purpose-disassembly-blue) ![Purpose: exploit%20generation](https://img.shields.io/badge/Purpose-exploit%20generation-blue) ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue) ![Purpose: lifting](https://img.shields.io/badge/Purpose-lifting-blue) ![Purpose: symbolic%20execution](https://img.shields.io/badge/Purpose-symbolic%20execution-blue) ![Purpose: value--set%20analysis](https://img.shields.io/badge/Purpose-value--set%20analysis-blue)
- **[angr-management](https://github.com/angr/angr-management)**
    - Description: GUI for the above-mentioned angr
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: control--flow%20analysis](https://img.shields.io/badge/Purpose-control--flow%20analysis-blue) ![Purpose: data--dependency%20analysis](https://img.shields.io/badge/Purpose-data--dependency%20analysis-blue) ![Purpose: decompilation](https://img.shields.io/badge/Purpose-decompilation-blue) ![Purpose: disassembly](https://img.shields.io/badge/Purpose-disassembly-blue) ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue) ![Purpose: lifting](https://img.shields.io/badge/Purpose-lifting-blue) ![Purpose: symbolic%20execution](https://img.shields.io/badge/Purpose-symbolic%20execution-blue) ![Purpose: value--set%20analysis](https://img.shields.io/badge/Purpose-value--set%20analysis-blue)
- **Approximating Attack Surfaces with Stack Traces**
    - Description: identification of attack surface given a stack trace
    - Type: ![Type: paper](https://img.shields.io/badge/Type-paper-lightgrey)
    - Purpose: ![Purpose: attack%20surface%20approximation](https://img.shields.io/badge/Purpose-attack%20surface%20approximation-blue)
- **[Awesome Fuzzing](https://github.com/secfigo/Awesome-Fuzzing)**
    - Description: list with fuzzing resources
    - Type: ![Type: awesome](https://img.shields.io/badge/Type-awesome-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[BAP](https://github.com/BinaryAnalysisPlatform/bap)**
    - Description: binary analysis platform
    - Type: ![Type: library](https://img.shields.io/badge/Type-library-lightgrey) ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: binary%20analysis](https://img.shields.io/badge/Purpose-binary%20analysis-blue) ![Purpose: lifting](https://img.shields.io/badge/Purpose-lifting-blue) ![Purpose: taint--analysis](https://img.shields.io/badge/Purpose-taint--analysis-blue)
- **[boofuzz](https://github.com/jtpereyda/boofuzz)**
    - Description: network fuzzer based on specifications
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[cb-multios](https://github.com/trailofbits/cb-multios)**
    - Description: dataset with the samples used in DARPA's Cyber Grand Challenge, migrated to multiple operating systems (Windows, Linux, MacOS)
    - Type: ![Type: dataset](https://img.shields.io/badge/Type-dataset-lightgrey)
    - Purpose: ![Purpose: vulnerability%20detection](https://img.shields.io/badge/Purpose-vulnerability%20detection-blue)
- **[Connected Papers](https://www.connectedpapers.com/)**
    - Description: papers search engine and graphing tool
    - Type: ![Type: website](https://img.shields.io/badge/Type-website-lightgrey)
    - Purpose: ![Purpose: research](https://img.shields.io/badge/Purpose-research-blue)
- **[CWE Enumeration](https://cwe.mitre.org/data/definitions/699.html)**
    - Description: weaknesses enumeration
    - Type: ![Type: enumeration](https://img.shields.io/badge/Type-enumeration-lightgrey)
    - Purpose: ![Purpose: vulnerability%20detection](https://img.shields.io/badge/Purpose-vulnerability%20detection-blue)
- **[Frida](https://frida.re/)**
    - Description: dynamic binary analysis framework for function hooking, tracing and scripting
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: dynamic%20analysis](https://img.shields.io/badge/Purpose-dynamic%20analysis-blue) ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue)
- **[Fuzzgoat](https://github.com/fuzzstati0n/fuzzgoat)**
    - Description: vulnerable C program with several memory corruption bugs
    - Type: ![Type: dataset](https://img.shields.io/badge/Type-dataset-lightgrey)
    - Purpose: ![Purpose: vulnerability%20detection](https://img.shields.io/badge/Purpose-vulnerability%20detection-blue)
- **[Fuzzing with AFL](https://github.com/mykter/afl-training)**
    - Description: AFL fuzzing workshop
    - Type: ![Type: workshop](https://img.shields.io/badge/Type-workshop-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[Ghidra](https://github.com/NationalSecurityAgency/ghidra)**
    - Description: reverse engineering tool
    - Type: ![Type: library](https://img.shields.io/badge/Type-library-lightgrey) ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: decompilation](https://img.shields.io/badge/Purpose-decompilation-blue)
- **[GhidraSnippets](https://github.com/HackOvert/GhidraSnippets)**
    - Description: Python snippets for working with Ghidra API
    - Type: ![Type: code%20snippets](https://img.shields.io/badge/Type-code%20snippets-lightgrey)
    - Purpose: ![Purpose: static%20analysis](https://img.shields.io/badge/Purpose-static%20analysis-blue)
- **[go-fuzz-corpus](https://github.com/dvyukov/go-fuzz-corpus)**
    - Description: corpus for fuzzing different file formats
    - Type: ![Type: dataset](https://img.shields.io/badge/Type-dataset-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[HaCRS](https://github.com/ucsb-seclab/hacrs)**
    - Description: a human-assisted cyber reasoning system
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue)
- **[Honggfuzz](https://github.com/google/honggfuzz)**
    - Description: evolutionary, coverage-based fuzzer
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **Instrumentarea dinamica a binarelor pentru fuzzing în SASHA**
    - Description: study case for binary instrumentation as in SASHA
    - Type: ![Type: study%20case](https://img.shields.io/badge/Type-study%20case-lightgrey)
    - Purpose: ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue)
- **[LIEF](https://lief-project.github.io/doc/latest/index.html)**
    - Description: Python 3 library for processing, modifying, and abstracting executable file
    - Type: ![Type: library](https://img.shields.io/badge/Type-library-lightgrey)
    - Purpose: ![Purpose: executables%20parsing](https://img.shields.io/badge/Purpose-executables%20parsing-blue)
- **[Manticore](https://github.com/trailofbits/manticore)**
    - Description: symbolic execution tool
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue) ![Purpose: symbolic%20execution](https://img.shields.io/badge/Purpose-symbolic%20execution-blue)
- **Mayhem Solution Brief**
    - Description: solution brief for Mayhem cyber reasoning system
    - Type: ![Type: brief](https://img.shields.io/badge/Type-brief-lightgrey)
    - Purpose: ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue)
- **[Mechanical Phish](https://github.com/mechaphish)**
    - Description: GitHub organization containing the components of the Mechanical Phish cyber reasoning system 
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue)
- **[NIST's C Test Suite](https://github.com/CyberReasoningSystem/nist_c_test_suite)**
    - Description: dataset containing the samples of C Test Suite
    - Type: ![Type: dataset](https://img.shields.io/badge/Type-dataset-lightgrey)
    - Purpose: ![Purpose: vulnerability%20detection](https://img.shields.io/badge/Purpose-vulnerability%20detection-blue)
- **[NIST's Juliet 1.3 Test Suite](https://github.com/arichardson/juliet-test-suite-c)**
    - Description: dataset containing the samples of Juliet 1.3
    - Type: ![Type: dataset](https://img.shields.io/badge/Type-dataset-lightgrey)
    - Purpose: ![Purpose: vulnerability%20detection](https://img.shields.io/badge/Purpose-vulnerability%20detection-blue)
- **[PDF.js](https://github.com/mozilla/pdf.js/tree/master/test/pdfs)**
    - Description: dataset containing PDFs used to test the Mozilla's in-browser reader
    - Type: ![Type: dataset](https://img.shields.io/badge/Type-dataset-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[Peach](https://github.com/MozillaSecurity/peach)**
    - Description: generational fuzzer
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **Practical Binary Analysis**
    - Description: cookbook for homemade binary analysis
    - Type: ![Type: book](https://img.shields.io/badge/Type-book-lightgrey)
    - Purpose: ![Purpose: binary%20analysis](https://img.shields.io/badge/Purpose-binary%20analysis-blue) ![Purpose: disassembly](https://img.shields.io/badge/Purpose-disassembly-blue) ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue) ![Purpose: loading](https://img.shields.io/badge/Purpose-loading-blue) ![Purpose: symbolic%20execution](https://img.shields.io/badge/Purpose-symbolic%20execution-blue) ![Purpose: taint%20analysis](https://img.shields.io/badge/Purpose-taint%20analysis-blue)
- **[Qiling Framework](https://github.com/qilingframework/qiling)**
    - Description: cross-platform, multi arch and QEMU-based lightweight emulator
    - Type: ![Type: library](https://img.shields.io/badge/Type-library-lightgrey)
    - Purpose: ![Purpose: emulator](https://img.shields.io/badge/Purpose-emulator-blue) ![Purpose: sandbox](https://img.shields.io/badge/Purpose-sandbox-blue)
- **[retrowrite](https://github.com/HexHive/retrowrite)**
    - Description: platform for instrumenting user-mode and kernel binaries with ASan and AFL
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: binary%20rewriting](https://img.shields.io/badge/Purpose-binary%20rewriting-blue) ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue) ![Purpose: static%20analysis](https://img.shields.io/badge/Purpose-static%20analysis-blue)
- **[revng](https://github.com/revng/revng)**
    - Description: static binary translator capable of instrumenting
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: binary%20rewriting](https://img.shields.io/badge/Purpose-binary%20rewriting-blue) ![Purpose: instrumentation](https://img.shields.io/badge/Purpose-instrumentation-blue) ![Purpose: static%20analysis](https://img.shields.io/badge/Purpose-static%20analysis-blue)
- **Rise of the HaCRS**
    - Description: description of a human-assisted cyber reasoning system, HaCRS
    - Type: ![Type: paper](https://img.shields.io/badge/Type-paper-lightgrey)
    - Purpose: ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue)
- **[River](https://github.com/unibuc-cs/river)**
    - Description: fuzzer using AI
    - Type: ![Type: tool](https://img.shields.io/badge/Type-tool-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **[Sci-Hub](https://sci-hub.se/)**
    - Description: papers database
    - Type: ![Type: website](https://img.shields.io/badge/Type-website-lightgrey)
    - Purpose: ![Purpose: research](https://img.shields.io/badge/Purpose-research-blue)
- **Survey of Automated Vulnerability Detection and Exploit Generation Techniques in Cyber Reasoning Systems**
    - Description: self-explanatory
    - Type: ![Type: paper](https://img.shields.io/badge/Type-paper-lightgrey)
    - Purpose: ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue) ![Purpose: exploit%20generation](https://img.shields.io/badge/Purpose-exploit%20generation-blue) ![Purpose: vulnerability%20detection](https://img.shields.io/badge/Purpose-vulnerability%20detection-blue)
- **[The Fuzzing Book](https://www.fuzzingbook.org/)**
    - Description: book with practical examples related to fuzzing
    - Type: ![Type: book](https://img.shields.io/badge/Type-book-lightgrey) ![Type: workshop](https://img.shields.io/badge/Type-workshop-lightgrey)
    - Purpose: ![Purpose: fuzzing](https://img.shields.io/badge/Purpose-fuzzing-blue)
- **The Mayhem Cyber Reasoning System**
    - Description: presentation of Mayhem as in Cyber Grand Challenge
    - Type: ![Type: publication](https://img.shields.io/badge/Type-publication-lightgrey)
    - Purpose: ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue)
- **Xandra: An Autonomous Cyber Battle System for the Cyber Grand Challenge**
    - Description: presentation of Xandra as in Cyber Grand Challenge
    - Type: ![Type: publication](https://img.shields.io/badge/Type-publication-lightgrey)
    - Purpose: ![Purpose: cyber%20reasoning%20system](https://img.shields.io/badge/Purpose-cyber%20reasoning%20system-blue)


## Contribution

1. Edit the `resources.csv` file.
2. Push the changes into the GitHub repository.
3. Wait for the GitHub action to automatically recompile `README.md`.