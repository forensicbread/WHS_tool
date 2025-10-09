# LLM Forensic Artifact Extraction Tool
#
# 지정된 E01 포렌식 이미지에서 LLM(Large Language Model) 애플리케-이션의 아티팩트를 추출한다.
# dfVFS 라이브러리를 사용하여 파일 시스템에 접근하고, 정의된 경로 패턴에 따라 파일을 검색 및 복사한다.
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
    import pytsk3  # noqa: F401
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import pytsk3. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

try:
    if not IS_MOCK_MODE:
        import dfvfs.vfs.tsk_file_entry  # noqa: F401
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
# --- PROGRESS BAR START ---
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
# --- PROGRESS BAR END ---

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
    if IS_MOCK_MODE:
        return MockDir(name='\\'), None
    try:
        os_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_OS, location=str(image_path))
        ewf_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_EWF, parent=os_path_spec)
        volume_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_TSK_PARTITION, location='/p3', parent=ewf_path_spec)
        fs_path_spec = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_NTFS, location='/', parent=volume_path_spec)
        resolver = path_spec_resolver.Resolver()
        root_entry = resolver.OpenFileEntry(fs_path_spec)
        if not root_entry:
            fs_path_spec_raw = path_spec_factory.Factory.NewPathSpec(definitions.TYPE_INDICATOR_NTFS, location='/', parent=ewf_path_spec)
            root_entry = resolver.OpenFileEntry(fs_path_spec_raw)
        if not root_entry:
            console.print("[red]Error[/red]: Could not mount NTFS filesystem."); return None, None
        return root_entry, fs_path_spec
    except Exception as e:
        console.print(f"[red]Error[/red]: dfVFS backend error: {e}"); return None, None


def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter):
    category_key = str(extract_category)
    if category_key not in collected_paths:
        collected_paths[category_key] = []
    if not path_parts:
        extract_item(root_entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter); return

    current_part, remaining_parts = path_parts[0], path_parts[1:]
    is_directory = (hasattr(root_entry, 'IsDirectory') and root_entry.IsDirectory()) or getattr(root_entry, 'is_directory', False)
    if not is_directory: return

    try:
        if current_part == '*':
            for sub_entry in root_entry._GetSubFileEntries():
                name_str = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
                if name_str in ['.', '..']: continue
                recursive_search_and_extract(sub_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, collected_paths, counter)
        else:
            found_entries = []
            if '*' in current_part:
                pattern = re.compile(current_part.replace('.', r'\.').replace('*', '.*'), re.IGNORECASE)
                for entry in root_entry._GetSubFileEntries():
                    file_name = entry.name.decode('utf-8', 'ignore') if isinstance(entry.name, bytes) else entry.name
                    if pattern.match(file_name): found_entries.append(entry)
            else:
                for entry in root_entry._GetSubFileEntries():
                    file_name = entry.name.decode('utf-8', 'ignore') if isinstance(entry.name, bytes) else entry.name
                    if file_name.upper() == current_part.upper(): found_entries.append(entry); break
            for found_entry in found_entries:
                name_str = found_entry.name.decode('utf-8', 'ignore') if isinstance(found_entry.name, bytes) else found_entry.name
                recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, collected_paths, counter)
    except Exception as e:
        error_message = f"[EXTRACTION_FAILED] Could not read directory '{'/'.join(current_path_parts)}': {e}"
        if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)


def extract_item(entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter):
    is_file = (hasattr(entry, 'IsFile') and entry.IsFile()) or getattr(entry, 'is_file', False)
    is_directory = (hasattr(entry, 'IsDirectory') and entry.IsDirectory()) or getattr(entry, 'is_directory', False)
    original_full_path = '/' + '/'.join(current_path_parts)
    category_key = str(extract_category)

    if original_full_path not in collected_paths[category_key]:
        collected_paths[category_key].append(original_full_path)

    if "extract_files" in artifact_info and is_directory:
        target_files_upper = [f.upper() for f in artifact_info["extract_files"]]
        try:
            for sub_entry in entry._GetSubFileEntries():
                sub_name = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
                if sub_name.upper() in target_files_upper:
                    new_info = {"extract_from": sub_name}
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], new_info, collected_paths, counter)
        except Exception as e:
            error_message = f"[EXTRACTION_FAILED] Failed to list items in directory '{original_full_path}': {e}"
            if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)
        return

    relative_path_parts = []
    extract_root_name = artifact_info.get("extract_from", "").upper().replace('\\', '/').split('/')[-1]
    if extract_root_name:
        upper_path_parts = [p.upper() for p in current_path_parts]
        try:
            start_index = upper_path_parts.index(extract_root_name)
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
            with open(output_target, 'wb') as outfile:
                file_object = entry.GetFileObject()
                if file_object:
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
            for sub_entry in entry._GetSubFileEntries():
                sub_name = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
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


def write_extracted_paths_log(collected_paths, program_output_dir, image_name, keep_plus=True):
    path_log_file_path = Path(program_output_dir) / "extracted_paths.txt"
    with open(path_log_file_path, 'w', encoding='utf-8') as f:
        f.write(f"--- LLM Forensic Artifacts Extracted Paths (Source Image: {image_name}) ---\n")
        f.write(f"--- Timestamp: {datetime.now().isoformat()} ---\n")
        for category_key, paths in sorted(collected_paths.items()):
            header = category_key if keep_plus else category_key.replace('_', '+')
            f.write(f"\n\n## {header}\n")
            f.write("---\n")
            for p in sorted(paths):
                f.write(f"- {p}\n")
    return path_log_file_path


def parse_args():
    parser = argparse.ArgumentParser(
        description="WHS_tool: Extracts forensic artifacts of LLM applications from an E01 image.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python %(prog)s ./E01/CHATGPT.E01 api CHATGPT ./result"
    )
    parser.add_argument("E01_IMAGE_PATH", help="Path to the E01 image file to be analyzed.")
    parser.add_argument("MODE", choices=["api", "standalone"], help="LLM operation mode.")
    parser.add_argument("LLM_NAME", choices=list(LLM_ARTIFACTS.keys()), help="Name of the LLM program to extract artifacts from.")
    parser.add_argument("OUTPUT_DIR", help="Path to the output directory where artifacts will be saved.")
    parser.add_argument("--no-keep-plus", action="store_true", help="Replace '+' with '_' in category folder names.")
    parser.add_argument("--no-show-summary", action="store_true", help="Disable the final summary table.")
    # Renamed from --no-kr-summary for clarity
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
    if llm_name_upper not in MODE_MAP.get(args.MODE, []):
        console.print(f"\n[red]Error[/red]: '{args.LLM_NAME}' does not belong to the '{args.MODE}' mode.")
        sys.exit(1)

    program_output_dir = Path(args.OUTPUT_DIR) / llm_name_upper
    program_output_dir.mkdir(parents=True, exist_ok=True)

    header_panel(args.E01_IMAGE_PATH, llm_name_upper, args.MODE, str(program_output_dir.resolve()))

    console.print(f"[INFO] Opening image file: {args.E01_IMAGE_PATH}")
    root_entry, _ = get_image_root_entry(e01_image_path)
    if root_entry is None: sys.exit(1)
    console.print("[INFO] Filesystem root entry confirmed.")

    artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]
    console.print(f"[INFO] Starting artifact search for {len(artifacts_to_extract)} categories...")

    collected_paths = {}
    
    # --- PROGRESS BAR START ---
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Processing categories...", total=len(artifacts_to_extract))

        # --- Main extraction loop ---
        for category, artifacts in artifacts_to_extract.items():
            category_key = category if not args.no_keep_plus else category.replace('+', '_')
            path_category_key = Path(category_key)
            label = category_key.replace('_', ' ')
            
            progress.update(task, description=f"[yellow]Processing: {label}...")
            
            collected_paths[category_key] = []
            
            for artifact_info in artifacts:
                full_path = artifact_info["path"]
                path_parts = normalize_path(full_path).split('/')
                counter = {'count': 0}
                recursive_search_and_extract(
                    root_entry, path_parts, program_output_dir,
                    path_category_key, [], artifact_info,
                    collected_paths, counter
                )
            
            if IS_MOCK_MODE: time.sleep(0.5) # Simulate work in mock mode
            progress.update(task, advance=1)
        
        progress.update(task, description="[green]Extraction complete!")

    console.print("[INFO] Extraction process finished. Finalizing results...")
    # --- PROGRESS BAR END ---
    
    # This loop is now for post-run console output only
    for category_key in collected_paths.keys():
        paths = collected_paths[category_key]
        succeeded = sum(1 for p in paths if not str(p).startswith("[EXTRACTION_FAILED]"))
        failed = len(paths) - succeeded
        label = category_key.replace('_', ' ')
        
        if failed > 0:
            console.print(f"[red][ALERT][/red] {label}: {succeeded} extracted, {failed} failed")
        else:
            console.print(f"[green][INFO][/green] {label}: {succeeded} extracted, {failed} failed")


    path_log_file_path = write_extracted_paths_log(collected_paths, program_output_dir, e01_image_path.name, keep_plus=not args.no_keep_plus)
    
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