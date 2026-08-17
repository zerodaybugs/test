from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import pefile
from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64
from capstone.arm64 import ARM64_OP_IMM
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

INPUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"C:\Windows\System32\vmfirmwarehcl.dll")
OUTPUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("evidence/embedded-analysis")
OUTPUT.mkdir(parents=True, exist_ok=True)

TARGETS: dict[str, bytes] = {
    "source_hclattest": b"onecore\\vm\\hcl\\fw\\security\\hclattest.cpp",
    "parse_jwt_assert": b"!Details::ParseJWTBlob(Payload, body)",
    "get_key_hsm_assert": b"!Details::GetKeyHsm(body, keyHsm)",
    "get_wrapped_key_assert": b"!Details::GetWrappedKey(payload, WrappedKey, false)",
    "key_hsm_json": b'"key_hsm"',
    "ciphertext_json": b'"ciphertext"',
    "root_cert_thumbprint": b'"root-cert-thumbprint":"',
    "vmgs_datastore_source": b"onecore\\vm\\hcl\\fw\\vmgs\\vmgsdatastore.cpp",
    "vmgs_root_key_error": "Failed to use the root key provided to decrypt VMGS metadata key.".encode("utf-16le"),
}

SECURITY_TERMS = [
    b"JWT", b"jwt", b"x5c", b"RS256", b"signature", b"Signature", b"certificate",
    b"Certificate", b"cert chain", b"trust anchor", b"thumbprint", b"root_cert_thumbprint",
    b"key_hsm", b"ciphertext", b"ParseJWTBlob", b"GetKeyHsm", b"GetWrappedKey",
    b"Guest Secret Key", b"VMGS", b"IGVM", b"attest", b"Attest",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def find_all(data: bytes, needle: bytes) -> list[int]:
    result: list[int] = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return result
        result.append(pos)
        start = pos + 1


def safe_name(value: str, limit: int = 180) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value[-limit:]


def file_offset_to_rva(pe: pefile.PE, offset: int) -> int | None:
    if 0 <= offset < pe.OPTIONAL_HEADER.SizeOfHeaders:
        return offset
    for section in pe.sections:
        start = int(section.PointerToRawData)
        end = start + int(section.SizeOfRawData)
        if start <= offset < end:
            return int(section.VirtualAddress) + (offset - start)
    return None


def rva_to_file_offset(pe: pefile.PE, rva: int) -> int | None:
    if 0 <= rva < pe.OPTIONAL_HEADER.SizeOfHeaders:
        return rva
    for section in pe.sections:
        start = int(section.VirtualAddress)
        span = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if start <= rva < start + span:
            offset = int(section.PointerToRawData) + (rva - start)
            if offset < int(section.PointerToRawData) + int(section.SizeOfRawData):
                return offset
    return None


def parse_codeview(pe: pefile.PE, module: bytes) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
        entries = getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])
    except Exception:
        entries = []
    for item in entries:
        struct_item = item.struct
        pointer = int(getattr(struct_item, "PointerToRawData", 0))
        size = int(getattr(struct_item, "SizeOfData", 0))
        blob = module[pointer:pointer + size]
        row: dict[str, Any] = {
            "type": int(getattr(struct_item, "Type", 0)),
            "pointer_to_raw_data": pointer,
            "size": size,
            "sha256": sha256(blob),
        }
        if blob.startswith(b"RSDS") and len(blob) >= 24:
            raw_guid = blob[4:20]
            age = struct.unpack_from("<I", blob, 20)[0]
            data1, data2, data3 = struct.unpack_from("<IHH", raw_guid, 0)
            data4 = raw_guid[8:]
            guid = f"{data1:08X}{data2:04X}{data3:04X}{data4.hex().upper()}"
            pdb_path = blob[24:].split(b"\0", 1)[0].decode("utf-8", "replace")
            row.update({
                "format": "RSDS",
                "guid": guid,
                "age": age,
                "symbol_server_key": f"{guid}{age:X}",
                "pdb_path": pdb_path,
                "pdb_name": Path(pdb_path.replace("\\", "/")).name,
            })
        output.append(row)
    return output


def download_public_pdb(codeview: list[dict[str, Any]], destination: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for row in codeview:
        pdb_name = row.get("pdb_name")
        key = row.get("symbol_server_key")
        if not pdb_name or not key:
            continue
        url = f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{key}/{pdb_name}"
        pdb_path = destination / safe_name(pdb_name)
        result: dict[str, Any] = {"pdb_name": pdb_name, "symbol_server_key": key, "downloaded": False}
        try:
            with urllib.request.urlopen(url, timeout=45) as response:
                data = response.read()
            pdb_path.write_bytes(data)
            result.update({"downloaded": True, "size": len(data), "sha256": sha256(data), "path": str(pdb_path)})
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            result["error"] = repr(error)
        results.append(result)
    return results


@dataclass(frozen=True)
class FunctionRange:
    begin_rva: int
    end_rva: int


def exception_functions(pe: pefile.PE) -> list[FunctionRange]:
    ranges: list[FunctionRange] = []
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
        for entry in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []):
            begin = int(entry.struct.BeginAddress)
            end = int(entry.struct.EndAddress)
            if 0 < begin < end:
                ranges.append(FunctionRange(begin, end))
    except Exception:
        pass
    ranges.sort(key=lambda item: item.begin_rva)
    return ranges


def function_for_rva(ranges: list[FunctionRange], rva: int) -> FunctionRange | None:
    lo, hi = 0, len(ranges)
    while lo < hi:
        mid = (lo + hi) // 2
        if ranges[mid].begin_rva <= rva:
            lo = mid + 1
        else:
            hi = mid
    if lo == 0:
        return None
    candidate = ranges[lo - 1]
    return candidate if candidate.begin_rva <= rva < candidate.end_rva else None


def section_bytes(pe: pefile.PE, module: bytes, name_prefix: bytes = b".text") -> tuple[Any, bytes] | None:
    for section in pe.sections:
        name = section.Name.rstrip(b"\0")
        if name.startswith(name_prefix) or (int(section.Characteristics) & 0x20000000):
            start = int(section.PointerToRawData)
            end = start + int(section.SizeOfRawData)
            return section, module[start:end]
    return None


def disassembler(machine: int) -> Cs | None:
    if machine == pefile.MACHINE_TYPE.get("IMAGE_FILE_MACHINE_AMD64", 0x8664):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif machine == pefile.MACHINE_TYPE.get("IMAGE_FILE_MACHINE_ARM64", 0xAA64):
        md = Cs(CS_ARCH_ARM64, CS_MODE_64)
    else:
        return None
    md.detail = True
    return md


def instruction_records(pe: pefile.PE, module: bytes) -> tuple[list[Any], dict[int, Any]]:
    text_info = section_bytes(pe, module)
    if text_info is None:
        return [], {}
    section, code = text_info
    md = disassembler(int(pe.FILE_HEADER.Machine))
    if md is None:
        return [], {}
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    start_va = image_base + int(section.VirtualAddress)
    instructions = list(md.disasm(code, start_va))
    by_address = {int(insn.address): insn for insn in instructions}
    return instructions, by_address


def xrefs_to_vas(pe: pefile.PE, instructions: list[Any], target_vas: dict[str, list[int]]) -> list[dict[str, Any]]:
    flattened: list[tuple[str, int]] = [(name, va) for name, vas in target_vas.items() for va in vas]
    output: list[dict[str, Any]] = []
    machine = int(pe.FILE_HEADER.Machine)
    for insn in instructions:
        references: list[int] = []
        if machine == 0x8664:
            for operand in insn.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    references.append(int(insn.address + insn.size + operand.mem.disp))
                elif operand.type == X86_OP_IMM:
                    references.append(int(operand.imm))
        elif machine == 0xAA64:
            for operand in insn.operands:
                if operand.type == ARM64_OP_IMM:
                    references.append(int(operand.imm))
        for reference in references:
            for name, target_va in flattened:
                if target_va <= reference < target_va + len(TARGETS[name]):
                    output.append({
                        "instruction_va": int(insn.address),
                        "instruction": f"{insn.mnemonic} {insn.op_str}".strip(),
                        "target": name,
                        "target_va": target_va,
                        "resolved_reference": reference,
                    })
    return output


def format_instruction(insn: Any) -> str:
    raw = bytes(insn.bytes).hex()
    return f"{int(insn.address):016X}  {raw:<30}  {insn.mnemonic:<8} {insn.op_str}".rstrip()


def direct_call_targets(pe: pefile.PE, instructions: Iterable[Any]) -> list[int]:
    result: list[int] = []
    machine = int(pe.FILE_HEADER.Machine)
    for insn in instructions:
        if not insn.mnemonic.lower().startswith(("call", "bl")):
            continue
        for operand in insn.operands:
            if machine == 0x8664 and operand.type == X86_OP_IMM:
                result.append(int(operand.imm) - int(pe.OPTIONAL_HEADER.ImageBase))
            elif machine == 0xAA64 and operand.type == ARM64_OP_IMM:
                result.append(int(operand.imm) - int(pe.OPTIONAL_HEADER.ImageBase))
    return result


def dump_function_graph(
    pe: pefile.PE,
    module: bytes,
    instructions: list[Any],
    by_address: dict[int, Any],
    ranges: list[FunctionRange],
    seed_rvas: Iterable[int],
    depth: int = 3,
) -> tuple[list[dict[str, Any]], str]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    queue: list[tuple[int, int, str]] = [(rva, 0, "seed") for rva in seed_rvas]
    visited: set[int] = set()
    rows: list[dict[str, Any]] = []
    text_lines: list[str] = []

    while queue:
        rva, level, reason = queue.pop(0)
        function = function_for_rva(ranges, rva)
        if function is None:
            continue
        if function.begin_rva in visited:
            continue
        visited.add(function.begin_rva)
        begin_va = image_base + function.begin_rva
        end_va = image_base + function.end_rva
        function_instructions = [insn for insn in instructions if begin_va <= int(insn.address) < end_va]
        calls = direct_call_targets(pe, function_instructions)
        row = {
            "begin_rva": function.begin_rva,
            "end_rva": function.end_rva,
            "size": function.end_rva - function.begin_rva,
            "depth": level,
            "reason": reason,
            "instruction_count": len(function_instructions),
            "direct_call_rvas": calls,
        }
        rows.append(row)
        text_lines.append(f"===== FUNCTION RVA 0x{function.begin_rva:X}-0x{function.end_rva:X} depth={level} reason={reason} =====")
        text_lines.extend(format_instruction(insn) for insn in function_instructions[:5000])
        text_lines.append("")
        if level < depth:
            for call_rva in calls:
                child = function_for_rva(ranges, call_rva)
                if child is not None and child.begin_rva not in visited:
                    queue.append((call_rva, level + 1, f"called_from_0x{function.begin_rva:X}"))
    return rows, "\n".join(text_lines)


def parse_pe_candidate(parent: bytes, offset: int) -> tuple[pefile.PE, bytes, int] | None:
    try:
        preliminary = pefile.PE(data=parent[offset:], fast_load=False)
        if int(preliminary.DOS_HEADER.e_magic) != 0x5A4D:
            return None
        raw_end = max(
            int(preliminary.OPTIONAL_HEADER.SizeOfHeaders),
            *(int(section.PointerToRawData) + int(section.SizeOfRawData) for section in preliminary.sections),
        )
        if raw_end <= 0 or raw_end > 64 * 1024 * 1024 or offset + raw_end > len(parent):
            return None
        module = parent[offset:offset + raw_end]
        pe = pefile.PE(data=module, fast_load=False)
        return pe, module, raw_end
    except Exception:
        return None


def enumerate_parent_resources(path: Path, data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        parent = pefile.PE(data=data, fast_load=False)
        parent.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception as error:
        return [{"error": repr(error)}]

    def label(entry: Any) -> str:
        if getattr(entry, "name", None) is not None:
            return str(entry.name)
        return str(getattr(entry, "id", "unknown"))

    root = getattr(parent, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return []
    for type_entry in root.entries:
        for name_entry in type_entry.directory.entries:
            for lang_entry in name_entry.directory.entries:
                rva = int(lang_entry.data.struct.OffsetToData)
                size = int(lang_entry.data.struct.Size)
                offset = parent.get_offset_from_rva(rva)
                blob = data[offset:offset + size]
                rows.append({
                    "type": label(type_entry),
                    "name": label(name_entry),
                    "language": label(lang_entry),
                    "rva": rva,
                    "file_offset": offset,
                    "size": size,
                    "sha256": sha256(blob),
                    "magic_hex": blob[:32].hex(),
                    "fv_header_offsets": find_all(blob, b"_FVH")[:100],
                    "mz_offsets": find_all(blob, b"MZ")[:1000],
                    "te_offsets": find_all(blob, b"VZ")[:1000],
                    "target_hits": {
                        key: find_all(blob, value)[:100]
                        for key, value in TARGETS.items()
                        if value in blob
                    },
                })
    return rows


def main() -> int:
    data = INPUT.read_bytes()
    (OUTPUT / "INPUT_METADATA.json").write_text(json.dumps({
        "path": str(INPUT),
        "size": len(data),
        "sha256": sha256(data),
        "target_absolute_offsets": {key: find_all(data, value) for key, value in TARGETS.items()},
    }, indent=2), encoding="utf-8")

    resources = enumerate_parent_resources(INPUT, data)
    (OUTPUT / "RESOURCE_INVENTORY.json").write_text(json.dumps(resources, indent=2), encoding="utf-8")

    mz_offsets = find_all(data, b"MZ")
    candidates: list[dict[str, Any]] = []
    candidate_modules: list[tuple[dict[str, Any], pefile.PE, bytes]] = []
    seen: set[tuple[int, int]] = set()
    for offset in mz_offsets:
        parsed = parse_pe_candidate(data, offset)
        if parsed is None:
            continue
        pe, module, raw_end = parsed
        key = (offset, raw_end)
        if key in seen:
            continue
        seen.add(key)
        target_hits = {name: find_all(module, value) for name, value in TARGETS.items() if value in module}
        security_hits = {
            term.decode("utf-8", "replace"): find_all(module, term)[:100]
            for term in SECURITY_TERMS
            if term in module
        }
        codeview = parse_codeview(pe, module)
        row: dict[str, Any] = {
            "parent_file_offset": offset,
            "raw_span": raw_end,
            "sha256": sha256(module),
            "machine": int(pe.FILE_HEADER.Machine),
            "number_of_sections": int(pe.FILE_HEADER.NumberOfSections),
            "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
            "entrypoint_rva": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "size_of_image": int(pe.OPTIONAL_HEADER.SizeOfImage),
            "sections": [{
                "name": section.Name.rstrip(b"\0").decode("ascii", "replace"),
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_offset": int(section.PointerToRawData),
                "raw_size": int(section.SizeOfRawData),
                "characteristics": int(section.Characteristics),
            } for section in pe.sections],
            "target_hits": target_hits,
            "security_term_hits": security_hits,
            "codeview": codeview,
        }
        candidates.append(row)
        if target_hits:
            candidate_modules.append((row, pe, module))

    (OUTPUT / "NESTED_PE_INVENTORY.json").write_text(json.dumps(candidates, indent=2), encoding="utf-8")

    selected_rows: list[dict[str, Any]] = []
    for index, (row, pe, module) in enumerate(candidate_modules, 1):
        selected_dir = OUTPUT / f"selected_{index:02d}_{row['parent_file_offset']:08X}_{row['sha256'][:16]}"
        selected_dir.mkdir(parents=True, exist_ok=True)
        codeview = row["codeview"]
        pdb_temp = selected_dir / "pdb-temp"
        pdb_temp.mkdir(exist_ok=True)
        pdb_downloads = download_public_pdb(codeview, pdb_temp)
        pdb_dumps: list[dict[str, Any]] = []
        llvm_pdbutil = os.environ.get("LLVM_PDBUTIL") or "llvm-pdbutil.exe"
        for pdb in pdb_downloads:
            if not pdb.get("downloaded"):
                continue
            dump_path = selected_dir / f"{safe_name(pdb['pdb_name'])}.symbols.txt"
            try:
                process = subprocess.run(
                    [llvm_pdbutil, "dump", "-publics", "-symbols", "-modules", pdb["path"]],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=180,
                )
                dump_path.write_bytes(process.stdout)
                pdb_dumps.append({"returncode": process.returncode, "output": str(dump_path), "size": len(process.stdout)})
            except Exception as error:
                pdb_dumps.append({"error": repr(error)})
            try:
                Path(pdb["path"]).unlink()
            except OSError:
                pass
        try:
            pdb_temp.rmdir()
        except OSError:
            pass

        target_vas: dict[str, list[int]] = {}
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        for name, offsets in row["target_hits"].items():
            vas: list[int] = []
            for file_offset in offsets:
                rva = file_offset_to_rva(pe, int(file_offset))
                if rva is not None:
                    vas.append(image_base + rva)
            target_vas[name] = vas

        instructions, by_address = instruction_records(pe, module)
        ranges = exception_functions(pe)
        xrefs = xrefs_to_vas(pe, instructions, target_vas)
        seed_rvas = [int(item["instruction_va"]) - image_base for item in xrefs]
        graph_rows, graph_text = dump_function_graph(pe, module, instructions, by_address, ranges, seed_rvas, depth=3)
        (selected_dir / "FUNCTION_GRAPH_DISASSEMBLY.txt").write_text(graph_text, encoding="utf-8")
        (selected_dir / "XREFS.json").write_text(json.dumps(xrefs, indent=2), encoding="utf-8")
        (selected_dir / "FUNCTION_GRAPH.json").write_text(json.dumps(graph_rows, indent=2), encoding="utf-8")

        ascii_strings = []
        for match in re.finditer(rb"[\x20-\x7e]{6,}", module):
            value = match.group().decode("ascii", "replace")
            if re.search(r"(?i)(jwt|x5c|rs256|signature|certificate|cert chain|thumbprint|key_hsm|ciphertext|wrappedkey|attest|vmgs|igvm)", value):
                ascii_strings.append({"offset": match.start(), "value": value})
        (selected_dir / "SECURITY_STRINGS.json").write_text(json.dumps(ascii_strings, indent=2), encoding="utf-8")

        selected = dict(row)
        selected.update({
            "target_vas": target_vas,
            "instruction_count": len(instructions),
            "exception_function_count": len(ranges),
            "xrefs": xrefs,
            "function_graph": graph_rows,
            "pdb_downloads": [{key: value for key, value in item.items() if key != "path"} for item in pdb_downloads],
            "pdb_dumps": pdb_dumps,
            "security_string_count": len(ascii_strings),
            "analysis_directory": selected_dir.name,
        })
        (selected_dir / "MODULE_ANALYSIS.json").write_text(json.dumps(selected, indent=2), encoding="utf-8")
        selected_rows.append(selected)

    gate = {
        "schema": "vmfirmwarehcl_embedded_hcl_source_binding/v1",
        "input": str(INPUT),
        "input_sha256": sha256(data),
        "resource_count": len(resources),
        "valid_nested_pe_count": len(candidates),
        "selected_nested_pe_count": len(selected_rows),
        "selected_modules": [{
            "parent_file_offset": row["parent_file_offset"],
            "sha256": row["sha256"],
            "machine": row["machine"],
            "target_hits": row["target_hits"],
            "xrefs_count": len(row["xrefs"]),
            "exception_function_count": row["exception_function_count"],
            "pdb_downloads": row["pdb_downloads"],
            "analysis_directory": row["analysis_directory"],
        } for row in selected_rows],
        "signed_binary_contains_hclattest_and_vmgs": any(
            "source_hclattest" in row["target_hits"] and "vmgs_datastore_source" in row["target_hits"]
            for row in selected_rows
        ),
        "signed_binary_contains_parse_jwt_key_hsm_path": any(
            all(name in row["target_hits"] for name in ("parse_jwt_assert", "get_key_hsm_assert", "key_hsm_json"))
            for row in selected_rows
        ),
        "binary_semantics_proven_vulnerable": False,
        "product_runtime_trigger_proven": False,
        "azure_service_binding_proven": False,
        "submission_ready": False,
        "note": "Static source-path and call-graph evidence can close implementation lineage but not responder-authentication semantics or Azure service reachability by itself.",
    }
    (OUTPUT / "GATE.json").write_text(json.dumps(gate, indent=2), encoding="utf-8")

    for path in sorted(OUTPUT.rglob("*")):
        if path.is_file():
            rel = path.relative_to(OUTPUT).as_posix()
            print(f"{sha256(path.read_bytes())}  {rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
