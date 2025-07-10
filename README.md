# Binary Ninja Swift Analyzer Plugin

A Binary Ninja plugin for analyzing Swift binaries

![Plugin demo movie](./img/demo.gif)

## Description

Swift binaries contain multiple type-related metadata. This metadata is often helpful in reverse engineering.
However, many disassemblers do not parse this type metadata, which poses a significant challenge when analyzing Swift binaries.
This plugin solves this problem by providing the following features:
- Parsing type metadata accessor and type metadata
- Analyzing PWT for structs and classes
- Identifying class methods
- Analyzing Swift immortal and large strings
- Visualizing protocol conformance and class inheritance

## Installation

1. Install [SwiftMetadataDump](./SwiftMetadataDump/README.md)
2. Install this plugin by placing this repository's content in `~/Library/Application Support/Binary Ninja/plugins`
3. Restart Binary Ninja

## Author

Koh M. Nakagawa (@tsunek0h). &copy; FFRI Security, Inc. 2025

## License

This plugin is released under the [Apache License, Version 2.0](LICENSE).
