#
# (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
#
import binaryninja
from dataclasses import dataclass
from binaryninja.flowgraph import (
    FlowGraph,
    FlowGraphNode,
    BranchType,
    EdgeStyle,
    EdgePenStyle,
    ThemeColor,
)
from binaryninja.interaction import (
    get_large_choice_input
)
from binaryninja.enums import HighlightStandardColor
import os
import subprocess
import json
import sys
from typing import Optional, List, Dict, Union
from functools import cached_property
import hashlib


@dataclass
class TypeBase:
    name: str
    node: Optional[FlowGraphNode]


@dataclass
class Struct(TypeBase):
    type_metadata_addr: Optional[int]
    type_metadata_accessor: Optional[int]
    witness_table_addr: List[int]
    conforming_protocols: List["Protocol"]


@dataclass
class Class(TypeBase):
    type_metadata_addr: Optional[int]
    type_metadata_accessor: Optional[int]
    parent_class: Optional["Class"]
    child_classes: List["Class"]
    witness_table_addr: List[int]
    conforming_protocols: List["Protocol"]
    vtable_methods: List[int]
    vtable_method_names: List[str]


@dataclass
class Protocol(TypeBase):
    conformed_types: List[Union[Struct, Class]]


def create_type(
    kind: int,
    name: str,
    type_metadata_addr: Optional[int],
    type_metadata_accessor: Optional[int],
) -> TypeBase:
    # See https://github.com/blacktop/go-macho/blob/688e64e88cc5b1c4ce788ea86ed58a2fe90e17b8/types/swift/types.go#L370-L401
    match kind:
        case 16:
            return Class(
                name,
                None,
                type_metadata_addr,
                type_metadata_accessor,
                None,
                [],
                [],
                [],
                [],
                [],
            )
        case 17:
            return Struct(
                name, None, type_metadata_addr, type_metadata_accessor, [], []
            )
        case 3:
            return Protocol(name, None, [])
        case _:
            print(f"Unsupported type kind: {kind}", file=sys.stderr)
            return None


class SwiftMetadata:
    def __init__(self, bv: binaryninja.BinaryView):
        self.bv = bv
        self.path = bv.file.original_filename
        print(f"Original file name: {bv.file}")
        if not os.path.exists(self.path):
            print(
                f"Cannot find {self.path}. Did you delete or move it before?",
                file=sys.stderr,
            )
            self.path = None
        self.extract_all()

    @cached_property
    def type_metadata(self) -> Optional[dict]:
        if self.path:
            return run_swift_metadata_dump(self.path, "types", self.bv.arch.name)
        else:
            print("Original file is not found", file=sys.stderr)
            return None

    @cached_property
    def protocol_metadata(self) -> Optional[dict]:
        if self.path:
            return run_swift_metadata_dump(self.path, "protocols", self.bv.arch.name)
        else:
            print("Original file is not found", file=sys.stderr)
            return None

    def extract_class_inheritance(
        self, types: Dict[str, Class]
    ) -> Dict[str, Class]:
        if self.type_metadata is None:
            return types
        for m in self.type_metadata:
            module_name = (
                m["Parent"]["Name"]
                if "Parent" in m.keys()
                and m["Parent"] is not None
                and "Name" in m["Parent"].keys()
                and m["Parent"]["Name"]
                else "<Unknown>"
            )
            type_name = m["Name"]
            full_type_name = f"{module_name}.{type_name}"
            if (
                "SuperClass" not in m["Type"].keys()
                or (super_class := m["Type"]["SuperClass"]) is None
            ):
                print(f"Super class is not found for {full_type_name}")
                continue
            if not super_class:
                print(f"Super class is not found for {full_type_name}")
                continue
            if super_class not in types.keys():
                print(f"Adding super class {super_class}")
                types[super_class] = create_type(16, super_class, None, None)

            types[full_type_name].parent_class = types[super_class]
            types[super_class].child_classes.append(types[full_type_name])

        return types

    def extract_vtable_entries(
        self, types: Dict[str, Union[Class, Struct]]
    ) -> Dict[str, List[int]]:
        # See https://github.com/blacktop/go-macho/blob/c4f8bca01ab2630cdf3b4c0f8314c6d8a73bf4d7/types/swift/types.go#L93-L221
        if self.type_metadata is None:
            return types
        for m in self.type_metadata:
            module_name = (
                m["Parent"]["Name"]
                if "Parent" in m.keys()
                and m["Parent"] is not None
                and "Name" in m["Parent"].keys()
                and m["Parent"]["Name"]
                else "<Unknown>"
            )
            type_name = m["Name"]
            full_type_name = f"{module_name}.{type_name}"

            if (
                "VTable" not in m["Type"].keys()
                or (vtable := m["Type"]["VTable"]) is None
            ):
                print(f"VTable is not found for {full_type_name}")
                continue

            for method in vtable["Methods"]:
                if method["Impl"]["RelOff"] == 0:
                    print(f"Impl is not set, so this method for {full_type_name} is stripped")
                    continue
                prefix = ""
                if method["Flags"] & 0x10 == 0:
                    prefix = "static "

                func_addr = method["Address"]
                symbol = (
                    method["Symbol"]
                    if method["Symbol"]
                    else f"sub_{hex(func_addr)[2:]}"
                )
                symbol = f"{prefix}{symbol}"
                types[full_type_name].vtable_methods.append(func_addr)
                types[full_type_name].vtable_method_names.append(symbol)
        return types

    def extract_protocol_conformance(
        self, types: Dict[str, Union[Class, Struct, Protocol]]
    ) -> Dict[str, Union[Class, Struct, Protocol]]:
        # See https://github.com/blacktop/go-macho/blob/c4f8bca01ab2630cdf3b4c0f8314c6d8a73bf4d7/types/swift/protocols.go#L426
        if self.protocol_metadata is None:
            return types
        for m in self.protocol_metadata:
            try:
                protocol_name = m["Protocol"]
                if m["WitnessTablePatternOffsest"]["RelOff"] == 0:
                    witness_table_pattern_addr = None
                else:
                    witness_table_pattern_addr = (
                        m["WitnessTablePatternOffsest"]["Address"]
                        + m["WitnessTablePatternOffsest"]["RelOff"]
                    )

                module_name = "<Unknown>"
                if "Parent" in m["TypeRef"].keys():
                    if (
                        m["TypeRef"]["Parent"] is not None
                        and "Name" in m["TypeRef"]["Parent"].keys()
                    ):
                        if m["TypeRef"]["Parent"]["Name"]:
                            module_name = m["TypeRef"]["Parent"]["Name"]

                type_name = m["TypeRef"]["Name"]
                full_type_name = f"{module_name}.{type_name}"
                if protocol_name not in types.keys():
                    print(f"Adding protocol {protocol_name} as a new protocol")
                    types[protocol_name] = Protocol(protocol_name, None, [])

                if full_type_name not in types.keys():
                    print(f"Adding type {full_type_name}")
                    typ = create_type(m["TypeRef"]["Kind"], full_type_name, None, None)
                    if typ is not None:
                        types[full_type_name] = typ
                    else:
                        print(f"Failed to add type {full_type_name} because of unsupported type kind", file=sys.stderr)

                types[protocol_name].conformed_types.append(types[full_type_name])
                types[full_type_name].conforming_protocols.append(types[protocol_name])
                types[full_type_name].witness_table_addr.append(
                    witness_table_pattern_addr
                )
            except Exception as e:
                print(
                    f"Exception occurs while extracting protocol conformance info {e}",
                    file=sys.stderr,
                )
                continue
        return types

    def extract_types(self) -> Dict[str, Union[Class, Struct, Protocol]]:
        # See https://github.com/blacktop/go-macho/blob/c4f8bca01ab2630cdf3b4c0f8314c6d8a73bf4d7/types/swift/types.go#L222-L300
        types = {}
        if self.type_metadata is None:
            return {}
        for m in self.type_metadata:
            try:
                module_name = (
                    m["Parent"]["Name"]
                    if "Parent" in m.keys()
                    and m["Parent"] is not None
                    and "Name" in m["Parent"].keys()
                    and m["Parent"]["Name"]
                    else "<Unknown>"
                )
                type_ = m["Type"]
                type_name = m["Name"]
                full_type_name = f"{module_name}.{type_name}"

                access_function = type_["AccessFunctionPtr"]
                if access_function["RelOff"] == 0:
                    print("Access function is not set")
                    type_metadata_accessor = None
                else:
                    type_metadata_accessor = (
                        access_function["Address"] + access_function["RelOff"]
                    )

                type_metadata_addr = get_function_return_imm(
                    self.bv, type_metadata_accessor
                )
                if type_metadata_addr is None:
                    print(
                        f"Type metadata for {full_type_name} is not statically determined"
                    )

                typ = create_type(
                    m["Kind"],
                    full_type_name,
                    type_metadata_addr,
                    type_metadata_accessor,
                )
                if typ is not None:
                    print(f"Adding type {full_type_name}")
                    types[full_type_name] = typ
                else:
                    print(f"Failed to add type {full_type_name} because of unsupported type kind", file=sys.stderr)

            except Exception as e:
                print(
                    f"Exception occurs while extracting all types {e}", file=sys.stderr
                )
                continue
        return types

    def extract_all(self):
        self.types = self.extract_types()
        self.types = self.extract_vtable_entries(self.types)
        self.types = self.extract_protocol_conformance(self.types)
        self.types = self.extract_class_inheritance(self.types)

    def find_type(self, name: str) -> Optional[Union[Class, Struct, Protocol]]:
        for _, typ in self.types.items():
            if typ.name.split(".")[-1] in name:
                return typ
        return None

    def clear_graph_nodes(self):
        for _, typ in self.types.items():
            typ.node = None

    @staticmethod
    def create_graph_node(graph: FlowGraph, typ: Union[Class, Struct, Protocol]) -> FlowGraphNode:
        if isinstance(typ, Class) or isinstance(typ, Struct):
            node = FlowGraphNode(graph)
            node.lines = [typ.name]
            if isinstance(typ, Class):
                node.highlight = HighlightStandardColor.OrangeHighlightColor
            else:
                node.highlight = HighlightStandardColor.RedHighlightColor
            graph.append(node)
            return node
        elif isinstance(typ, Protocol):
            node = FlowGraphNode(graph)
            node.lines = [typ.name]
            node.highlight = HighlightStandardColor.BlueHighlightColor
            graph.append(node)
            return node
        else:
            raise ValueError(f"Unsupported type: {typ}")

    def create_graph_nodes_and_edges_parent_classes_recursively(self, graph: FlowGraph, typ: Class) -> None:
        if typ.parent_class is not None:
            typ.parent_class.node = self.create_graph_node(graph, typ.parent_class)
            edge = EdgeStyle(EdgePenStyle.DashDotLine, 2, ThemeColor.AddressColor)
            typ.parent_class.node.add_outgoing_edge(BranchType.UserDefinedBranch, typ.node, edge)
            for protocol in typ.parent_class.conforming_protocols:
                protocol.node = self.create_graph_node(graph, protocol)
                edge = EdgeStyle(EdgePenStyle.SolidLine, 2, ThemeColor.AddressColor)
                protocol.node.add_outgoing_edge(BranchType.UserDefinedBranch, typ.parent_class.node, edge)
            return self.create_graph_nodes_and_edges_parent_classes_recursively(graph, typ.parent_class)
        return

    def create_graph_nodes_and_edges(self, typ: Union[Class, Struct, Protocol]) -> FlowGraph:
        self.clear_graph_nodes()
        graph = FlowGraph()
        typ.node = self.create_graph_node(graph, typ)

        if isinstance(typ, Class) or isinstance(typ, Struct):
            for protocol in typ.conforming_protocols:
                protocol.node = self.create_graph_node(graph, protocol)
                edge = EdgeStyle(EdgePenStyle.SolidLine, 2, ThemeColor.AddressColor)
                protocol.node.add_outgoing_edge(BranchType.UserDefinedBranch, typ.node, edge)

        if isinstance(typ, Protocol):
            for conformed_type in typ.conformed_types:
                conformed_type.node = self.create_graph_node(graph, conformed_type)
                edge = EdgeStyle(EdgePenStyle.SolidLine, 2, ThemeColor.AddressColor)
                typ.node.add_outgoing_edge(BranchType.UserDefinedBranch, conformed_type.node, edge)

        if isinstance(typ, Class):
            self.create_graph_nodes_and_edges_parent_classes_recursively(graph, typ)

        return graph


    def create_all_graph_nodes(self) -> FlowGraph:
        self.clear_graph_nodes()
        graph = FlowGraph()
        for _, typ in self.types.items():
            typ.node = self.create_graph_node(graph, typ)
        return graph

    @cached_property
    def protocols(self) -> Dict[str, Protocol]:
        return {k: v for k, v in self.types.items() if isinstance(v, Protocol)}

    @cached_property
    def classes(self) -> Dict[str, Class]:
        return {k: v for k, v in self.types.items() if isinstance(v, Class)}

    @cached_property
    def structs(self) -> Dict[str, Struct]:
        return {k: v for k, v in self.types.items() if isinstance(v, Struct)}


class SwiftMetadataCache:
    _instance = None
    _cache: Dict[str, SwiftMetadata] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SwiftMetadataCache, cls).__new__(cls)
        return cls._instance

    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of the file content"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            # Read the file in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def get_metadata(self, bv: binaryninja.BinaryView) -> SwiftMetadata:
        try:
            file_hash = self._calculate_file_hash(bv.file.original_filename)
            if file_hash not in self._cache:
                self._cache[file_hash] = SwiftMetadata(bv)
            return self._cache[file_hash]
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            # Fallback to using filename as key if file is not found
            if bv.file.original_filename not in self._cache:
                self._cache[bv.file.original_filename] = SwiftMetadata(bv)
            return self._cache[bv.file.original_filename]

    def clear(self):
        self._cache.clear()


def get_swift_metadata(bv: binaryninja.BinaryView) -> SwiftMetadata:
    return SwiftMetadataCache().get_metadata(bv)


def show_conformance_inheritance_graph(bv: binaryninja.BinaryView):
    swift_metadata = get_swift_metadata(bv)

    selected_type_idx = get_large_choice_input("Select type", "Select a type", [typ.name for typ in swift_metadata.types.values()])
    selected_type = list(swift_metadata.types.values())[selected_type_idx]

    graph = swift_metadata.create_graph_nodes_and_edges(selected_type)
    bv.show_graph_report(f"Conformance/Inheritance of {selected_type.name}", graph)


def get_function_return_imm(bv: binaryninja.BinaryView, addr: int) -> Optional[int]:
    func = bv.get_function_at(addr)
    if func is None:
        return None

    for inst in func.hlil.instructions:
        if inst.operation == binaryninja.HighLevelILOperation.HLIL_RET and hasattr(
            inst, "operands"
        ):
            if hasattr(inst.operands[0][0], "constant"):
                return inst.operands[0][0].constant
    return None


def fix_caling_convention(bv: binaryninja.BinaryView):
    # usercall
    # https://github.com/doronz88/swift_reversing?tab=readme-ov-file#struct
    pass


def is_address_in_current_module(bv: binaryninja.BinaryView, addr: int) -> bool:
    for section in bv.sections.values():
        if section.start <= addr < section.end:
            return True
    return False


def get_large_immortal_swift_str_pointer(
    bv: binaryninja.BinaryView, value: int
) -> Optional[int]:
    if (
        (value & 0xF000000000000000) == 0x8000000000000000
    ) and is_address_in_current_module(bv, (value & 0x0FFFFFFFFFFFFFFF)):
        return (value & 0x0FFFFFFFFFFFFFFF) + 0x20
    return None


def set_swift_string_if_possible(bv: binaryninja.BinaryView, addr: int, value: int):
    if (swift_ptr := get_large_immortal_swift_str_pointer(bv, value)) is None:
        return
    if (swift_str := bv.get_string_at(swift_ptr)) is None:
        print(f"Failed to retrieve swift string @ {hex(swift_ptr)}", file=sys.stderr)
    bv.set_comment_at(addr, f"swift_str: {swift_str}")
    bv.add_user_data_ref(swift_ptr, addr)


def add_string_comments_at_function(
    bv: binaryninja.BinaryView, func: binaryninja.function.Function
):
    for hlil_inst in func.hlil.instructions:
        if hasattr(hlil_inst, "params"):
            for param in hlil_inst.params:
                if not hasattr(param, "constant"):
                    continue
                if not isinstance(param.constant, int):
                    continue
                set_swift_string_if_possible(bv, hlil_inst.address, param.constant)

        if hasattr(hlil_inst, "src"):
            if hasattr(hlil_inst.src, "constant") and isinstance(hlil_inst.src.constant, int):
                set_swift_string_if_possible(bv, hlil_inst.address, hlil_inst.src.constant)
            elif hasattr(hlil_inst.src, "params"):
                for param in hlil_inst.src.params:
                    if not hasattr(param, "constant"):
                        continue
                    if not isinstance(param.constant, int):
                        continue
                    set_swift_string_if_possible(bv, hlil_inst.address, param.constant)
            elif isinstance(hlil_inst.src, list) and len(hlil_inst.src) > 0 and hasattr(hlil_inst.src[0], "params"):
                for src in hlil_inst.src:
                    for param in src.params:
                        if not hasattr(param, "constant"):
                            continue
                        if not isinstance(param.constant, int):
                            continue
                        set_swift_string_if_possible(bv, hlil_inst.address, param.constant)

def add_string_comments_at(bv: binaryninja.BinaryView, addr: int):
    funcs = bv.get_functions_containing(addr)
    for func in funcs:
        add_string_comments_at_function(bv, func)


def add_string_comments_all(bv: binaryninja.BinaryView):
    for func in bv.functions:
        try:
            add_string_comments_at_function(bv, func)
        except Exception as e:
            print(e, file=sys.stderr)


def run_swift_demangle(s: str) -> Optional[str]:
    try:
        demangled_output = subprocess.run(
            ["xcrun", "swift-demangle"], input=s, capture_output=True, text=True
        ).stdout
    except Exception as e:
        print("Unknown error while running swift-demangle: " + e, file=sys.stderr)
        return None
    return demangled_output


def run_swift_metadata_dump(input_binary: str, metadata_type: str, arch: str) -> dict:
    home_dir = os.path.expanduser("~")
    swift_metadata_dump_path = os.path.join(home_dir, "go", "bin", "SwiftMetadataDump")
    if not os.path.exists(swift_metadata_dump_path):
        print("SwiftMetadataDump is not found. Please install it.", file=sys.stderr)
        return None

    # https://github.com/blacktop/go-macho/blob/c517c47afb0313ea86c0b3d303ecbe6c2e5381ad/types/cpu.go#L33-L49
    binja_arch_to_gomacho_arch = {
        "x86_64": "Amd64",
        "aarch64": "AARCH64",
    }
    if arch not in binja_arch_to_gomacho_arch.keys():
        print(f"Unsupported arch: {arch}. Please add it to binja_arch_to_gomacho_arch", file=sys.stderr)
        return None

    print(f"Running SwiftMetadataDump for {input_binary} with architecture {arch}")
    result = subprocess.run(
        [swift_metadata_dump_path, input_binary, metadata_type, binja_arch_to_gomacho_arch[arch]],
        capture_output=True,
        text=True,
    )
    if (demangled_output := run_swift_demangle(result.stdout)) is None:
        return None
    try:
        metadata = json.loads(demangled_output)
    except json.JSONDecodeError:
        print(
            "Failed to decode json output.\nThis might be because SwiftMetadataDump failed to execute",
            file=sys.stderr,
        )
        return None
    return metadata


def annotate_protocol_witness_table_methods(
    bv: binaryninja.BinaryView, input_binary: str
):
    pass


def annotate_class_methods(bv: binaryninja.BinaryView, classes: Dict[str, Class]):
    for cls_name, cls in classes.items():
        for symbol, method_addr in zip(cls.vtable_method_names, cls.vtable_methods):
            full_symbol = f"{cls_name}.{symbol}"
            existing_symbol = bv.get_symbol_at(method_addr)
            is_default_symbol = (
                existing_symbol is None or existing_symbol.name.startswith("sub_")
            )
            if is_default_symbol:
                print(f"Adding method {full_symbol} at {hex(method_addr)}")
                new_symbol = binaryninja.Symbol(
                    binaryninja.SymbolType.DataSymbol, method_addr, full_symbol
                )
                bv.define_user_symbol(new_symbol)


def annotate_protocol_witness(
    bv: binaryninja.BinaryView, types: Dict[str, Union[Struct, Class]]
):
    for _, typ in types.items():
        for protocol, witness_table_pattern_addr in zip(
            typ.conforming_protocols, typ.witness_table_addr
        ):
            if witness_table_pattern_addr is None:
                print(f"Witness table pattern address is not set for {typ.name} for {protocol.name}")
                continue
            print(f"Adding PWT of {typ.name} for {protocol.name} at {hex(witness_table_pattern_addr)}")
            new_symbol = binaryninja.Symbol(
                binaryninja.SymbolType.DataSymbol,
                witness_table_pattern_addr,
                f"pwt of {typ.name} for {protocol.name}",
            )
            bv.define_user_symbol(new_symbol)


def annotate_type_metadata(
    bv: binaryninja.BinaryView, types: Dict[str, Union[Struct, Class]]
):
    for _, typ in types.items():
        if typ.type_metadata_addr is not None:
            new_symbol = binaryninja.Symbol(
                binaryninja.SymbolType.DataSymbol,
                typ.type_metadata_addr,
                f"type metadata for {typ.name}",
            )
            bv.define_user_symbol(new_symbol)

        if typ.type_metadata_accessor is not None:
            new_symbol = binaryninja.Symbol(
                binaryninja.SymbolType.FunctionSymbol,
                typ.type_metadata_accessor,
                f"type metadata accessor for {typ.name}",
            )
            bv.define_user_symbol(new_symbol)


def add_static_type_metadata(bv: binaryninja.BinaryView):
    swift_metadata = get_swift_metadata(bv)

    classes = swift_metadata.classes
    structs = swift_metadata.structs

    annotate_type_metadata(bv, classes)
    annotate_type_metadata(bv, structs)
    annotate_protocol_witness(bv, classes)
    annotate_protocol_witness(bv, structs)
    annotate_class_methods(bv, classes)


def get_prev_instruction_addr(bv: binaryninja.BinaryView, addr: int) -> Optional[int]:
    funcs = bv.get_functions_containing(addr)
    if funcs:
        return funcs[0].get_instruction_containing_address(addr - 1)
    else:
        print(f"Cannot find function at {hex(addr)}", file=sys.stderr)
        return None


def load_dynamic_type_metadata(bv: binaryninja.BinaryView):
    input_json = binaryninja.get_open_filename_input("filename:", "*.json")
    with open(input_json, "r") as fin:
        raw_contents = fin.read()
        demangled_output = run_swift_demangle(raw_contents)
        metadata = json.loads(demangled_output)

    for addr, type_name in metadata:
        if (alloc_func_call_site := get_prev_instruction_addr(bv, addr)) is not None:
            bv.set_comment_at(alloc_func_call_site, f"type metadata: {type_name}")


binaryninja.PluginCommand.register(
    "Swift Analyzer\\Add static type metadata",
    "Extract type metadata and apply it",
    add_static_type_metadata,
)
binaryninja.PluginCommand.register(
    "Swift Analyzer\\Load dynamic type metadata",
    "Load dynamic type metadata",
    load_dynamic_type_metadata,
)
binaryninja.PluginCommand.register(
    "Swift Analyzer\\Add swift strings all",
    "Add swift string reference",
    add_string_comments_all,
)
binaryninja.PluginCommand.register_for_address(
    "Swift Analyzer\\Add swift strings at",
    "Add swift string reference",
    add_string_comments_at,
)
binaryninja.PluginCommand.register(
    "Swift Analyzer\\Show conformance/inheritance graph",
    "Show conformance/inheritance graph",
    show_conformance_inheritance_graph,
)
