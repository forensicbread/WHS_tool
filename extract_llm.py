# LLM Forensic Artifact Extraction Tool – WHS_tool UI Style
# Filename: extract_llm.py
#
# UI Highlights:
# - Header panel with tool name and run context
# - [INFO]/[ALERT] lines for each category as it's processed
# - Final "Extraction Complete" section with a styled summary table
# - English polite final summary
#
# Defaults: keep '+', summary table ON, final summary ON
# Opt-outs: --no-keep-plus --no-show-summary --no-final-summary
#
# Usage:
#   python extract_llm.py <E01_IMAGE_PATH> <MODE> <LLM_NAME> <OUTPUT_DIR>

import argparse
import sys
import re
from pathlib import Path
import json
from datetime import datetime
import time

IS_MOCK_MODE = False

try:
    import pytsk3
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import pytsk3. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

try:
    if not IS_MOCK_MODE:
        from dfvfs.lib import definitions
        from dfvfs.path import factory as path_spec_factory
        from dfvfs.resolver import resolver as path_spec_resolver
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import dfvfs modules. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.box import HEAVY_HEAD
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

# Simple mock fallback to allow dry-runs without native libs
if IS_MOCK_MODE:
    console.print("[yellow]Warning[/yellow]: Required forensic libraries not found. Running in [bold]Mock Mode[/bold].")

    class MockDir:
        def __init__(self, name): self.name = name
        def _GetSubFileEntries(self): return []
        def IsDirectory(self): return True

    class MockFile: pass


def load_artifact_definitions(file_path="artifacts.json"):
    try:
        script_dir = Path(__file__).parent
        config_path = script_dir / file_path
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]FATAL[/bold red]: Artifact definition file not found at '{config_path}'."); sys.exit(1)
    except json.JSONDecodeError:
        console.print(f"[bold red]FATAL[/bold red]: Failed to decode JSON from '{config_path}'."); sys.exit(1)


MODE_MAP = {
    "api": ["CHATGPT", "CLAUDE"],
    "standalone": ["LMSTUDIO", "JAN"],
}
LLM_ARTIFACTS = load_artifact_definitions()


def normalize_path(path: str) -> str:
    normalized = path.replace('\\', '/')
    if ':' in normalized and (normalized.find(':') < normalized.find('/') if '/' in normalized else True):
        normalized = normalized.split(':', 1)[-1]
    return normalized.upper().lstrip('/')


def get_image_root_entry(image_path: Path):
    """E01 이미지를 열고, 각 파티션을 순차적으로 직접 마운트하여 Windows 파티션을 찾습니다."""
    if IS_MOCK_MODE:
        return MockDir(name='\\'), None

    try:
        resolver = path_spec_resolver.Resolver
        os_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_OS, location=str(image_path)
        )
        ewf_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_EWF, parent=os_path_spec
        )
    except Exception as e:
        console.print(f"[bold red]FATAL[/bold red]: Could not initialize base path specs: {e}")
        return None, None

    # 최대 10개의 파티션을 순차적으로 검사
    for i in range(1, 11):
        try:
            partition_location = f'/p{i}'
            console.print(f"[INFO] Checking partition: [cyan]{partition_location}[/cyan]...")

            # EWF 컨테이너에서 직접 TSK 파티션 경로를 지정 (가장 안정적인 방식)
            partition_path_spec = path_spec_factory.Factory.NewPathSpec(
                definitions.TYPE_INDICATOR_TSK_PARTITION,
                location=partition_location,
                parent=ewf_path_spec
            )
            
            # 해당 파티션을 NTFS로 마운트 시도
            ntfs_path_spec = path_spec_factory.Factory.NewPathSpec(
                definitions.TYPE_INDICATOR_NTFS, location='/', parent=partition_path_spec
            )

            fs_root_entry = resolver.OpenFileEntry(ntfs_path_spec)

            # Windows 폴더가 있는지 확인하여 OS 파티션인지 최종 판단
            if fs_root_entry and fs_root_entry.GetSubFileEntryByName('Windows'):
                console.print(f"[green][SUCCESS][/green] Found Windows OS at partition: [bold]{partition_location}[/bold]")
                return fs_root_entry, ntfs_path_spec

        except Exception:
            # 해당 파티션이 없거나 NTFS가 아니면 조용히 다음으로 넘어감
            continue

    console.print("[bold red]FATAL[/bold red]: Could not find a partition containing a 'Windows' directory in the image.")
    return None, None

def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter):
    category_key = str(extract_category)
    if category_key not in collected_paths:
        collected_paths[category_key] = []
    if not path_parts:
        extract_item(root_entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter); return

    current_part, remaining_parts = path_parts[0], path_parts[1:]
    is_directory = root_entry.IsDirectory()
    if not is_directory: return

    try:
        if current_part == '*':
            for sub_entry in root_entry.sub_file_entries:
                name_str = sub_entry.name
                if name_str in ['.', '..']: continue
                recursive_search_and_extract(sub_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, collected_paths, counter)
        else:
            found_entries = []
            if '*' in current_part:
                pattern_str = '.*'.join(map(re.escape, current_part.split('*')))
                pattern = re.compile(pattern_str, re.IGNORECASE)
                for entry in root_entry.sub_file_entries:
                    file_name = entry.name
                    if pattern.match(file_name): found_entries.append(entry)
            else:
                # Attempt to get entry by name, case-sensitively first, then try case-insensitively if needed
                entry = root_entry.GetSubFileEntryByName(current_part)
                if not entry:
                    # Fallback for case-insensitive filesystems
                    for sub_entry in root_entry.sub_file_entries:
                        if sub_entry.name.lower() == current_part.lower():
                            entry = sub_entry
                            break
                if entry:
                    found_entries.append(entry)

            for found_entry in found_entries:
                name_str = found_entry.name
                recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, collected_paths, counter)
    except Exception as e:
        error_message = f"[EXTRACTION_FAILED] Could not read directory '{'/'.join(current_path_parts)}': {e}"
        if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)


def extract_item(entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter):
    is_file = entry.IsFile()
    is_directory = entry.IsDirectory()
    original_full_path = '/' + '/'.join(current_path_parts)
    category_key = str(extract_category)

    if original_full_path not in collected_paths[category_key]:
        collected_paths[category_key].append(original_full_path)

    if "extract_files" in artifact_info and is_directory:
        target_files_upper = [f.upper() for f in artifact_info["extract_files"]]
        try:
            for sub_entry in entry.sub_file_entries:
                sub_name = sub_entry.name
                if sub_name.upper() in target_files_upper:
                    new_info = {"extract_from": sub_name}
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], new_info, collected_paths, counter)
        except Exception as e:
            error_message = f"[EXTRACTION_FAILED] Failed to list items in directory '{original_full_path}': {e}"
            if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)
        return

    relative_path_parts = []
    extract_root_name = artifact_info.get("extract_from", "").upper().replace('\\', '/').split('/')[-1]
    if "{LLM_NAME}" in extract_root_name:
        llm_name_placeholder = artifact_info.get("llm_name_placeholder", "").upper()
        extract_root_name = extract_root_name.replace("{LLM_NAME}", llm_name_placeholder)

    if extract_root_name:
        upper_path_parts = [p.upper() for p in current_path_parts]
        try:
            start_index = len(upper_path_parts) - 1 - upper_path_parts[::-1].index(extract_root_name)
            relative_path_parts = current_path_parts[start_index:]
        except ValueError:
            relative_path_parts = [current_path_parts[-1]]
    else:
        relative_path_parts = [current_path_parts[-1]]

    output_target = Path(output_dir) / extract_category / Path(*relative_path_parts)

    if is_file:
        counter['count'] += 1
        output_target.parent.mkdir(parents=True, exist_ok=True)
        try:
            file_object = entry.GetFileObject()
            if file_object:
                with open(output_target, 'wb') as outfile:
                    while True:
                        chunk = file_object.read(1024 * 1024)
                        if not chunk: break
                        outfile.write(chunk)
                file_object.close()
        except Exception as e:
            error_message = f"[EXTRACTION_FAILED] Failed to write file '{original_full_path}' to '{output_target}': {e}"
            if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)
    elif is_directory:
        counter['count'] += 1
        output_target.mkdir(parents=True, exist_ok=True)
        try:
            for sub_entry in entry.sub_file_entries:
                sub_name = sub_entry.name
                if sub_name not in ['.', '..']:
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], artifact_info, collected_paths, counter)
        except Exception as e:
            error_message = f"[EXTRACTION_FAILED] Failed to process subdirectory in '{original_full_path}': {e}"
            if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)


def header_panel(image_path, llm_name, mode, output_dir):
    text = (
        f"[bold]WHS_tool – LLM Forensic Artifact Extraction[/bold]\n"
        f"\n"
        f"[dim]Analyzing Image:[/dim] {image_path}\n"
        f"[dim]LLM Target:[/dim] {llm_name} ({mode})\n"
        f"[dim]Output Directory:[/dim] {output_dir}"
    )
    panel = Panel(Align.left(text), border_style="cyan", padding=(1,2))
    console.print(panel)


def final_summary(collected_paths, llm_name, program_output_dir, path_log_file_path, keep_plus=True, show_table=True, show_final_summary=True):
    total_succeeded = 0
    total_failed = 0
    for paths in collected_paths.values():
        total_succeeded += sum(1 for p in paths if not str(p).startswith("[EXTRACTION_FAILED]"))
        total_failed += sum(1 for p in paths if str(p).startswith("[EXTRACTION_FAILED]"))

    if show_table:
        console.print()
        table = Table(
            title=Align.center("Artifact Extraction Summary"),
            show_header=True,
            header_style="bold",
            box=HEAVY_HEAD
        )
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Extracted", justify="right")
        table.add_column("Failed", justify="right")

        for category_key, paths in sorted(collected_paths.items()):
            label = category_key if keep_plus else category_key.replace("+", "_")
            succeeded = sum(1 for p in paths if not str(p).startswith("[EXTRACTION_FAILED]"))
            failed = sum(1 for p in paths if str(p).startswith("[EXTRACTION_FAILED]"))

            failed_str = f"[red]{failed}[/red]" if failed > 0 else str(failed)
            table.add_row(label, str(succeeded), failed_str)
        
        console.print(table)
        console.print()

    if show_final_summary:
        fail_msg = f"with [bold red]{total_failed}[/bold red] failures." if total_failed > 0 else "without any errors."
        console.print(f"[bold]Analysis for {llm_name.lower()} is complete.[/bold] Successfully extracted [bold green]{total_succeeded}[/bold green] artifacts {fail_msg}")
        console.print(f"Detailed success/failure paths can be found in the log file.")
        console.print(f"[dim]Log File:[/dim] {path_log_file_path.resolve()}")
        console.print(f"[dim]Result Folder:[/dim] {program_output_dir.resolve()}")


def write_extracted_paths_log(collected_paths, program_output_dir, image_name, llm_name, mode, keep_plus=True):
    """Generates a user-friendly, detailed log file of all found and failed artifact paths."""
    path_log_file_path = Path(program_output_dir) / "extraction_report.txt"
    
    total_succeeded = 0
    total_failed = 0
    for paths in collected_paths.values():
        total_succeeded += sum(1 for p in paths if not str(p).startswith("[EXTRACTION_FAILED]"))
        total_failed += sum(1 for p in paths if str(p).startswith("[EXTRACTION_FAILED]"))

    with open(path_log_file_path, 'w', encoding='utf-8') as f:
        f.write("===============================================================\n")
        f.write(" WHS_tool - LLM Forensic Artifact Extraction Log\n")
        f.write("===============================================================\n\n")

        f.write("Run Details\n")
        f.write("-----------\n")
        f.write(f"- Source Image: {image_name}\n")
        f.write(f"- LLM Target: {llm_name} (Mode: {mode})\n")
        f.write(f"- Output Directory: {program_output_dir.resolve()}\n")
        f.write(f"- Timestamp: {datetime.now().isoformat()}\n\n")

        f.write("Extraction Summary\n")
        f.write("------------------\n")
        f.write(f"- Categories Processed: {len(collected_paths)}\n")
        f.write(f"- Successful Extractions: {total_succeeded}\n")
        f.write(f"- Failed Extractions: {total_failed}\n\n")

        f.write("===============================================================\n")
        f.write(" Detailed Path Log\n")
        f.write("===============================================================\n")

        for category_key, paths in sorted(collected_paths.items()):
            header = category_key if keep_plus else category_key.replace('+', '_')
            succeeded = sum(1 for p in paths if not str(p).startswith("[EXTRACTION_FAILED]"))
            failed = len(paths) - succeeded
            
            f.write(f"\n\n## Category: {header} ({succeeded} succeeded, {failed} failed)\n")
            f.write("---------------------------------------------------------------\n")
            
            if not paths:
                f.write("- No paths found for this category.\n")
                continue

            sorted_paths = sorted(paths, key=lambda p: "ZZZ" if "[EXTRACTION_FAILED]" in p else p)

            for p in sorted_paths:
                if str(p).startswith("[EXTRACTION_FAILED]"):
                    status = "[FAILED] "
                    # Remove the prefix for cleaner logging
                    path_to_log = p.replace("[EXTRACTION_FAILED] ", "")
                else:
                    status = "[SUCCESS]"
                    path_to_log = p
                f.write(f"{status.ljust(10)} {path_to_log}\n")

        f.write("\n\n--- End of Report ---\n")
        
    return path_log_file_path

def parse_args():
    parser = argparse.ArgumentParser(
        description="WHS_tool: Extracts forensic artifacts of LLM applications from an E01 image.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python %(prog)s ./E01/CHATGPT.E01 api CHATGPT ./result"
    )
    parser.add_argument("E01_IMAGE_PATH", help="Path to the E01 image file to be analyzed.")
    parser.add_argument("MODE", choices=["api", "standalone"], help="LLM operation mode.")
    parser.add_argument("LLM_NAME", help="Name of the LLM program to extract artifacts from.")
    parser.add_argument("OUTPUT_DIR", help="Path to the output directory where artifacts will be saved.")
    parser.add_argument("--no-keep-plus", action="store_true", help="Replace '+' with '_' in category folder names.")
    parser.add_argument("--no-show-summary", action="store_true", help="Disable the final summary table.")
    parser.add_argument("--no-final-summary", action="store_true", help="Disable the final summary message.")
    return parser.parse_args()


def main():
    args = parse_args()

    e01_image_path = Path(args.E01_IMAGE_PATH)
    if not e01_image_path.is_file() and not IS_MOCK_MODE:
        console.print(f"\n[red]Error[/red]: The specified E01 image file does not exist or is not a file.")
        console.print(f"Provided path: {e01_image_path.resolve()}")
        sys.exit(1)

    llm_name_upper = args.LLM_NAME.upper()
    
    is_defined_llm = llm_name_upper in LLM_ARTIFACTS
    is_heuristic_mode = not is_defined_llm

    if not is_defined_llm:
        heuristic_key = f"_HEURISTICS_{args.MODE.upper()}"
        if heuristic_key not in LLM_ARTIFACTS:
            console.print(f"\n[red]Error[/red]: Heuristic definition '{heuristic_key}' not found in artifacts.json for unknown LLM '{args.LLM_NAME}'.")
            sys.exit(1)
        artifacts_to_extract = LLM_ARTIFACTS[heuristic_key]
    else:
        known_llms = [k for k in LLM_ARTIFACTS.keys() if not k.startswith('_')]
        if llm_name_upper in known_llms:
             pass
        artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]

    program_output_dir = Path(args.OUTPUT_DIR) / llm_name_upper
    program_output_dir.mkdir(parents=True, exist_ok=True)

    header_panel(args.E01_IMAGE_PATH, llm_name_upper, args.MODE, str(program_output_dir.resolve()))

    if is_heuristic_mode:
        console.print(f"[yellow]Warning[/yellow]: '{args.LLM_NAME}' is not a predefined LLM. Running in [bold]Heuristic Discovery Mode[/bold] for '{args.MODE}' mode.")

    console.print(f"[INFO] Opening image file: {args.E01_IMAGE_PATH}")
    root_entry, _ = get_image_root_entry(e01_image_path)
    if root_entry is None: sys.exit(1)

    console.print(f"[INFO] Starting artifact search for {len(artifacts_to_extract)} categories...")

    collected_paths = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Processing categories...", total=len(artifacts_to_extract))

        for category, artifacts in artifacts_to_extract.items():
            category_key = category if not args.no_keep_plus else category.replace('+', '_')
            path_category_key = Path(category_key)
            label = category_key.replace('_', ' ')
            
            progress.update(task, description=f"[yellow]Processing: {label}...")
            
            collected_paths[category_key] = []
            
            for artifact_info in artifacts:
                full_path = artifact_info["path"]
                if is_heuristic_mode:
                    full_path = full_path.replace("{LLM_NAME}", llm_name_upper)
                    artifact_info["llm_name_placeholder"] = llm_name_upper
                
                path_parts = normalize_path(full_path).split('/')
                counter = {'count': 0}
                recursive_search_and_extract(
                    root_entry, path_parts, program_output_dir,
                    path_category_key, [], artifact_info,
                    collected_paths, counter
                )
            
            if IS_MOCK_MODE: time.sleep(0.5)
            progress.update(task, advance=1)
        
        progress.update(task, description="[green]Extraction complete!")

    console.print("[INFO] Extraction process finished. Finalizing results...")
    
    for category_key in collected_paths.keys():
        paths = collected_paths[category_key]
        succeeded = sum(1 for p in paths if not str(p).startswith("[EXTRACTION_FAILED]"))
        failed = len(paths) - succeeded
        label = category_key.replace('_', ' ')
        
        if failed > 0:
            console.print(f"[red][ALERT][/red] {label}: {succeeded} extracted, {failed} failed")
        else:
            console.print(f"[green][INFO][/green] {label}: {succeeded} extracted, {failed} failed")


    path_log_file_path = write_extracted_paths_log(
        collected_paths=collected_paths,
        program_output_dir=program_output_dir,
        image_name=e01_image_path.name,
        llm_name=llm_name_upper,
        mode=args.MODE,
        keep_plus=not args.no_keep_plus
    )
    
    final_summary(
        collected_paths=collected_paths,
        llm_name=llm_name_upper,
        program_output_dir=program_output_dir,
        path_log_file_path=path_log_file_path,
        keep_plus=not args.no_keep_plus,
        show_table=not args.no_show_summary,
        show_final_summary=not args.no_final_summary
    )


if __name__ == "__main__":
    main()