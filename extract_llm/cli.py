# LLM Forensic Artifact Extraction Tool
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

# --- 전역 설정 ---

# 목 모드(Mock Mode) 플래그. 포렌식 라이브러리 없이 실행하기 위한 테스트용.
IS_MOCK_MODE = False

# --- 필수 라이브러리 임포트 및 목 모드 설정 ---

try:
    # pytsk3: Sleuth Kit 라이브러리의 파이썬 바인딩. 파일 시스템 분석의 핵심.
    import pytsk3
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import pytsk3. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

try:
    if not IS_MOCK_MODE:
        # dfVFS: 디지털 포렌식 가상 파일 시스템. E01 같은 이미지 파일을 쉽게 다루게 해줌.
        from dfvfs.lib import definitions
        from dfvfs.path import factory as path_spec_factory
        from dfvfs.resolver import resolver as path_spec_resolver
except Exception as e:
    print(f"**FATAL ERROR**: Failed to import dfvfs modules. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

# --- UI 및 콘솔 출력을 위한 Rich 라이브러리 설정 ---
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.box import HEAVY_HEAD
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

# 콘솔 객체 생성
console = Console()

# 목 모드일 경우 사용자에게 경고 메시지 출력
if IS_MOCK_MODE:
    console.print("[yellow]Warning[/yellow]: Required forensic libraries not found. Running in [bold]Mock Mode[/bold].")

    # 실제 파일 시스템 객체 대신 사용할 가짜 클래스 정의
    class MockDir:
        def __init__(self, name): self.name = name
        def _GetSubFileEntries(self): return []
        def IsDirectory(self): return True

    class MockFile: pass

# --- 함수 정의 ---

def load_artifact_definitions(file_path="artifacts.json"):
    """아티팩트 경로 정보가 담긴 JSON 파일을 로드하는 함수."""
    try:
        script_dir = Path(__file__).parent
        config_path = script_dir / file_path
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print(f"[bold red]FATAL[/bold red]: Artifact definition file not found at '{config_path}'."); sys.exit(1)
    except json.JSONDecodeError:
        console.print(f"[bold red]FATAL[/bold red]: Failed to decode JSON from '{config_path}'."); sys.exit(1)


# --- 아티팩트 정보 로드 및 전역 변수 설정 ---

# LLM 종류를 모드별로 매핑
MODE_MAP = {
    "api": ["CHATGPT", "CLAUDE"],
    "standalone": ["LMSTUDIO", "JAN"],
}
# JSON 파일에서 아티팩트 정보 로드
LLM_ARTIFACTS = load_artifact_definitions()


def normalize_path(path: str) -> str:
    """Windows 경로(\\)를 POSIX 경로(//)로 변환하고 드라이브 문자를 제거하는 정규화 함수."""
    normalized = path.replace('\\', '/')
    # C:/Users/... 같은 경로에서 'C:' 부분을 제거
    if ':' in normalized and (normalized.find(':') < normalized.find('/') if '/' in normalized else True):
        normalized = normalized.split(':', 1)[-1]
    return normalized.upper().lstrip('/')


def get_image_root_entry(image_path: Path):
    """E01 이미지를 열어 Windows OS가 설치된 파티션을 찾아 파일 시스템의 루트를 반환함."""
    if IS_MOCK_MODE:
        return MockDir(name='\\'), None

    try:
        # dfVFS 경로 명세(path spec) 설정 시작
        resolver = path_spec_resolver.Resolver
        # 1. OS 레벨에서 파일 경로 지정
        os_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_OS, location=str(image_path)
        )
        # 2. EWF 이미지 형식임을 지정
        ewf_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_EWF, parent=os_path_spec
        )
    except Exception as e:
        console.print(f"[bold red]FATAL[/bold red]: Could not initialize base path specs: {e}")
        return None, None

    # EWF 이미지 내 파티션을 p1부터 순서대로 최대 10개까지 확인
    for i in range(1, 11):
        try:
            partition_location = f'/p{i}'
            console.print(f"[INFO] Checking partition: [cyan]{partition_location}[/cyan]...")

            # 3. TSK 파티션 경로 지정 (예: /p1, /p2)
            partition_path_spec = path_spec_factory.Factory.NewPathSpec(
                definitions.TYPE_INDICATOR_TSK_PARTITION,
                location=partition_location,
                parent=ewf_path_spec
            )
            
            # 4. 해당 파티션을 NTFS 파일 시스템으로 마운트 시도
            ntfs_path_spec = path_spec_factory.Factory.NewPathSpec(
                definitions.TYPE_INDICATOR_NTFS, location='/', parent=partition_path_spec
            )

            # 파일 시스템의 루트 디렉터리 객체를 가져옴
            fs_root_entry = resolver.OpenFileEntry(ntfs_path_spec)

            # 'Windows' 폴더 존재 여부로 OS 파티션인지 최종 확인
            if fs_root_entry and fs_root_entry.GetSubFileEntryByName('Windows'):
                console.print(f"[green][SUCCESS][/green] Found Windows OS at partition: [bold]{partition_location}[/bold]")
                return fs_root_entry, ntfs_path_spec

        except Exception:
            # 해당 파티션이 없거나 NTFS가 아니면 오류 발생. 무시하고 다음으로 진행.
            continue
    
    # Windows 파티션을 찾지 못하면 프로그램 종료
    console.print("[bold red]FATAL[/bold red]: Could not find a partition containing a 'Windows' directory in the image.")
    return None, None

def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter):
    """정의된 경로 패턴을 따라 재귀적으로 파일을 탐색하고 추출을 요청하는 함수."""
    category_key = str(extract_category)
    if category_key not in collected_paths:
        collected_paths[category_key] = [] # 결과 기록용 딕셔너리 초기화
    
    # 경로의 마지막 부분에 도달하면 extract_item 함수 호출
    if not path_parts:
        extract_item(root_entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter); return

    current_part, remaining_parts = path_parts[0], path_parts[1:]
    if not root_entry.IsDirectory(): return # 현재 위치가 디렉터리가 아니면 탐색 중단

    try:
        # 와일드카드 '*' 처리: 현재 디렉터리의 모든 하위 항목에 대해 재귀 호출
        if current_part == '*':
            for sub_entry in root_entry.sub_file_entries:
                name_str = sub_entry.name
                if name_str in ['.', '..']: continue
                recursive_search_and_extract(sub_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, collected_paths, counter)
        else:
            found_entries = []
            # 'CHATGPT*.pf' 같은 패턴 매칭 처리
            if '*' in current_part:
                pattern_str = '.*'.join(map(re.escape, current_part.split('*')))
                pattern = re.compile(pattern_str, re.IGNORECASE)
                for entry in root_entry.sub_file_entries:
                    if pattern.match(entry.name): found_entries.append(entry)
            else:
                # 정확한 이름으로 파일/디렉터리 찾기 (대소문자 구분 시도 후 미구분으로 재시도)
                entry = root_entry.GetSubFileEntryByName(current_part)
                if not entry:
                    for sub_entry in root_entry.sub_file_entries:
                        if sub_entry.name.lower() == current_part.lower():
                            entry = sub_entry
                            break
                if entry:
                    found_entries.append(entry)

            # 찾은 각 항목에 대해 재귀적으로 탐색 계속
            for found_entry in found_entries:
                recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, current_path_parts + [found_entry.name], artifact_info, collected_paths, counter)
    
    except Exception as e:
        # 디렉터리 읽기 실패 시 오류 기록
        error_message = f"[EXTRACTION_FAILED] Could not read directory '{'/'.join(current_path_parts)}': {e}"
        if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)


def extract_item(entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter):
    """실제로 파일이나 디렉터리를 디스크에 복사(추출)하는 함수."""
    is_file = entry.IsFile()
    is_directory = entry.IsDirectory()
    original_full_path = '/' + '/'.join(current_path_parts)
    category_key = str(extract_category)

    # 추출된 경로를 로그에 기록
    if original_full_path not in collected_paths[category_key]:
        collected_paths[category_key].append(original_full_path)

    # "extract_files" 옵션이 있으면 디렉터리 내 특정 파일들만 추출
    if "extract_files" in artifact_info and is_directory:
        target_files_upper = [f.upper() for f in artifact_info["extract_files"]]
        try:
            for sub_entry in entry.sub_file_entries:
                if sub_entry.name.upper() in target_files_upper:
                    new_info = {"extract_from": sub_entry.name}
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_entry.name], new_info, collected_paths, counter)
        except Exception as e:
            error_message = f"[EXTRACTION_FAILED] Failed to list items in directory '{original_full_path}': {e}"
            if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)
        return

    # 결과 폴더에 저장될 상대 경로 계산
    relative_path_parts = []
    extract_root_name = artifact_info.get("extract_from", "").upper().replace('\\', '/').split('/')[-1]
    if "{LLM_NAME}" in extract_root_name: # 휴리스틱 모드용 플레이스홀더 처리
        llm_name_placeholder = artifact_info.get("llm_name_placeholder", "").upper()
        extract_root_name = extract_root_name.replace("{LLM_NAME}", llm_name_placeholder)

    if extract_root_name:
        upper_path_parts = [p.upper() for p in current_path_parts]
        try:
            # 'extract_from' 기준으로 경로를 잘라 상대 경로를 만듦
            start_index = len(upper_path_parts) - 1 - upper_path_parts[::-1].index(extract_root_name)
            relative_path_parts = current_path_parts[start_index:]
        except ValueError:
            relative_path_parts = [current_path_parts[-1]]
    else:
        relative_path_parts = [current_path_parts[-1]]
    
    # 최종적으로 파일이 저장될 경로 설정
    output_target = Path(output_dir) / extract_category / Path(*relative_path_parts)

    if is_file:
        counter['count'] += 1
        output_target.parent.mkdir(parents=True, exist_ok=True)
        try:
            # 파일 객체를 열어 청크 단위로 읽고 디스크에 씀
            file_object = entry.GetFileObject()
            if file_object:
                with open(output_target, 'wb') as outfile:
                    while True:
                        chunk = file_object.read(1024 * 1024) # 1MB씩 읽기
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
            # 디렉터리인 경우, 하위 항목들에 대해 재귀적으로 추출 함수 호출
            for sub_entry in entry.sub_file_entries:
                if sub_entry.name not in ['.', '..']:
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_entry.name], artifact_info, collected_paths, counter)
        except Exception as e:
            error_message = f"[EXTRACTION_FAILED] Failed to process subdirectory in '{original_full_path}': {e}"
            if error_message not in collected_paths[category_key]: collected_paths[category_key].append(error_message)


def header_panel(image_path, llm_name, mode, output_dir):
    """프로그램 시작 시 실행 정보를 보여주는 헤더 패널을 출력하는 함수."""
    text = (
        f"[bold]extract_llm – LLM Forensic Artifact Extraction[/bold]\n"
        f"\n"
        f"[dim]Analyzing Image:[/dim] {image_path}\n"
        f"[dim]LLM Target:[/dim] {llm_name} ({mode})\n"
        f"[dim]Output Directory:[/dim] {output_dir}"
    )
    panel = Panel(Align.left(text), border_style="cyan", padding=(1,2))
    console.print(panel)


def final_summary(collected_paths, llm_name, program_output_dir, path_log_file_path, keep_plus=True, show_table=True, show_final_summary=True):
    """프로그램 종료 시 추출 결과 요약 테이블과 최종 메시지를 출력하는 함수."""
    total_succeeded = sum(1 for paths in collected_paths.values() for p in paths if not str(p).startswith("[EXTRACTION_FAILED]"))
    total_failed = sum(1 for paths in collected_paths.values() for p in paths if str(p).startswith("[EXTRACTION_FAILED]"))

    # 요약 테이블 출력 (--no-show-summary 옵션으로 비활성화 가능)
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
            failed = len(paths) - succeeded
            failed_str = f"[red]{failed}[/red]" if failed > 0 else str(failed)
            table.add_row(label, str(succeeded), failed_str)
        
        console.print(table)
        console.print()

    # 최종 요약 메시지 출력 (--no-final-summary 옵션으로 비활성화 가능)
    if show_final_summary:
        fail_msg = f"with [bold red]{total_failed}[/bold red] failures." if total_failed > 0 else "without any errors."
        console.print(f"[bold]Analysis for {llm_name.lower()} is complete.[/bold] Successfully extracted [bold green]{total_succeeded}[/bold green] artifacts {fail_msg}")
        console.print(f"Detailed success/failure paths can be found in the log file.")
        console.print(f"[dim]Log File:[/dim] {path_log_file_path.resolve()}")
        console.print(f"[dim]Result Folder:[/dim] {program_output_dir.resolve()}")


def write_extracted_paths_log(collected_paths, program_output_dir, image_name, llm_name, mode, keep_plus=True):
    """추출된 모든 경로와 실패 정보를 상세 로그 파일로 저장하는 함수."""
    # 파일명은 extraction_report.txt (또는 .md)로 고정
    path_log_file_path = Path(program_output_dir) / "extraction_report.txt"
    
    total_succeeded = sum(1 for paths in collected_paths.values() for p in paths if not str(p).startswith("[EXTRACTION_FAILED]"))
    total_failed = sum(1 for paths in collected_paths.values() for p in paths if str(p).startswith("[EXTRACTION_FAILED]"))

    with open(path_log_file_path, 'w', encoding='utf-8') as f:
        # 헤더
        f.write("===============================================================\n")
        f.write(" extract_llm - LLM Forensic Artifact Extraction Log\n")
        f.write("===============================================================\n\n")

        # 실행 정보
        f.write("Run Details\n")
        f.write("-----------\n")
        f.write(f"- Source Image: {image_name}\n")
        f.write(f"- LLM Target: {llm_name} (Mode: {mode})\n")
        f.write(f"- Output Directory: {program_output_dir.resolve()}\n")
        f.write(f"- Timestamp: {datetime.now().isoformat()}\n\n")

        # 추출 요약
        f.write("Extraction Summary\n")
        f.write("------------------\n")
        f.write(f"- Categories Processed: {len(collected_paths)}\n")
        f.write(f"- Successful Extractions: {total_succeeded}\n")
        f.write(f"- Failed Extractions: {total_failed}\n\n")

        # 상세 경로 로그
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

            # 실패한 경로를 로그 하단에 정렬
            sorted_paths = sorted(paths, key=lambda p: "ZZZ" if "[EXTRACTION_FAILED]" in p else p)

            for p in sorted_paths:
                if str(p).startswith("[EXTRACTION_FAILED]"):
                    status = "[FAILED] "
                    path_to_log = p.replace("[EXTRACTION_FAILED] ", "")
                else:
                    status = "[SUCCESS]"
                    path_to_log = p
                f.write(f"{status.ljust(10)} {path_to_log}\n")

        f.write("\n\n--- End of Report ---\n")
        
    return path_log_file_path

def parse_args():
    """명령줄 인자(argument)를 파싱하는 함수."""
    parser = argparse.ArgumentParser(
        description="extract_llm: Extracts forensic artifacts of LLM applications from an E01 image.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python %(prog)s ./E01/CHATGPT.E01 api CHATGPT ./result"
    )
    # 필수 인자
    parser.add_argument("E01_IMAGE_PATH", help="Path to the E01 image file to be analyzed.")
    parser.add_argument("MODE", choices=["api", "standalone"], help="LLM operation mode.")
    parser.add_argument("LLM_NAME", help="Name of the LLM program to extract artifacts from.")
    parser.add_argument("OUTPUT_DIR", help="Path to the output directory where artifacts will be saved.")
    # 선택적 인자 (옵션)
    parser.add_argument("--no-keep-plus", action="store_true", help="Replace '+' with '_' in category folder names.")
    parser.add_argument("--no-show-summary", action="store_true", help="Disable the final summary table.")
    parser.add_argument("--no-final-summary", action="store_true", help="Disable the final summary message.")
    return parser.parse_args()


def main():
    """메인 실행 함수."""
    # 1. 명령줄 인자 파싱
    args = parse_args()

    # 2. 입력 파일 경로 확인
    e01_image_path = Path(args.E01_IMAGE_PATH)
    if not e01_image_path.is_file() and not IS_MOCK_MODE:
        console.print(f"\n[red]Error[/red]: The specified E01 image file does not exist or is not a file.")
        console.print(f"Provided path: {e01_image_path.resolve()}")
        sys.exit(1)

    llm_name_upper = args.LLM_NAME.upper()
    
    # 3. 분석 대상 LLM이 정의된 것인지, 아니면 휴리스틱 모드인지 판단
    is_defined_llm = llm_name_upper in LLM_ARTIFACTS
    is_heuristic_mode = not is_defined_llm

    if is_heuristic_mode:
        # 정의되지 않은 LLM이면, 모드(api/standalone)에 맞는 휴리스틱 패턴을 사용
        heuristic_key = f"_HEURISTICS_{args.MODE.upper()}"
        if heuristic_key not in LLM_ARTIFACTS:
            console.print(f"\n[red]Error[/red]: Heuristic definition '{heuristic_key}' not found in artifacts.json for unknown LLM '{args.LLM_NAME}'.")
            sys.exit(1)
        artifacts_to_extract = LLM_ARTIFACTS[heuristic_key]
    else:
        # 정의된 LLM이면 해당 LLM의 아티팩트 정보를 사용
        artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]

    # 4. 결과 저장 디렉터리 생성
    program_output_dir = Path(args.OUTPUT_DIR) / llm_name_upper
    program_output_dir.mkdir(parents=True, exist_ok=True)

    # 5. 헤더 출력
    header_panel(args.E01_IMAGE_PATH, llm_name_upper, args.MODE, str(program_output_dir.resolve()))

    if is_heuristic_mode:
        console.print(f"[yellow]Warning[/yellow]: '{args.LLM_NAME}' is not a predefined LLM. Running in [bold]Heuristic Discovery Mode[/bold] for '{args.MODE}' mode.")

    # 6. 포렌식 이미지 열기
    console.print(f"[INFO] Opening image file: {args.E01_IMAGE_PATH}")
    root_entry, _ = get_image_root_entry(e01_image_path)
    if root_entry is None: sys.exit(1)

    console.print(f"[INFO] Starting artifact search for {len(artifacts_to_extract)} categories...")

    collected_paths = {} # 추출된 경로를 저장할 딕셔너리
    
    # 7. 프로그레스 바와 함께 아티팩트 추출 실행
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True # 작업 완료 후 프로그레스 바를 화면에서 지움
    ) as progress:
        task = progress.add_task("[yellow]Processing categories...", total=len(artifacts_to_extract))

        # 각 카테고리(Program_Execution_Traces, Network 등) 별로 반복
        for category, artifacts in artifacts_to_extract.items():
            category_key = category if not args.no_keep_plus else category.replace('+', '_')
            path_category_key = Path(category_key)
            label = category_key.replace('_', ' ')
            
            progress.update(task, description=f"[yellow]Processing: {label}...")
            
            collected_paths[category_key] = []
            
            # 각 카테고리 내의 아티팩트 경로별로 반복
            for artifact_info in artifacts:
                full_path = artifact_info["path"]
                if is_heuristic_mode: # 휴리스틱 모드 시 경로의 {LLM_NAME}을 실제 이름으로 치환
                    full_path = full_path.replace("{LLM_NAME}", llm_name_upper)
                    artifact_info["llm_name_placeholder"] = llm_name_upper
                
                path_parts = normalize_path(full_path).split('/')
                counter = {'count': 0}
                # 재귀 탐색 및 추출 함수 호출
                recursive_search_and_extract(
                    root_entry, path_parts, program_output_dir,
                    path_category_key, [], artifact_info,
                    collected_paths, counter
                )
            
            if IS_MOCK_MODE: time.sleep(0.5) # 목 모드 시 시각적 효과를 위한 딜레이
            progress.update(task, advance=1)
        
        progress.update(task, description="[green]Extraction complete!")

    # 8. 중간 결과 출력
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

    # 9. 상세 로그 파일 작성
    path_log_file_path = write_extracted_paths_log(
        collected_paths=collected_paths,
        program_output_dir=program_output_dir,
        image_name=e01_image_path.name,
        llm_name=llm_name_upper,
        mode=args.MODE,
        keep_plus=not args.no_keep_plus
    )
    
    # 10. 최종 요약 정보 출력
    final_summary(
        collected_paths=collected_paths,
        llm_name=llm_name_upper,
        program_output_dir=program_output_dir,
        path_log_file_path=path_log_file_path,
        keep_plus=not args.no_keep_plus,
        show_table=not args.no_show_summary,
        show_final_summary=not args.no_final_summary
    )


# --- 스크립트 실행 시작점 ---
if __name__ == "__main__":
    main()