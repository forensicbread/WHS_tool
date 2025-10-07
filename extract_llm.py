import argparse
import os
import sys
import platform
import re
from pathlib import Path

# --- dfvfs 및 pytsk3 라이브러리 임포트 (기존과 동일) ---
IS_MOCK_MODE = False

try:
    import pytsk3
except ImportError as e:
    print(f"**치명적 오류**: pytsk3 임포트 실패. 원인: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

try:
    if not IS_MOCK_MODE:
        import dfvfs.vfs.tsk_file_entry
        from dfvfs.resolver import context
        from dfvfs.lib import definitions
        from dfvfs.path import path_spec as dfvfs_path_spec
        from dfvfs.path import factory as path_spec_factory
        from dfvfs.resolver import resolver as path_spec_resolver
        TSK_FS_NAME_TYPE_REG = pytsk3.TSK_FS_NAME_TYPE_REG
        TSK_FS_NAME_TYPE_DIR = pytsk3.TSK_FS_NAME_TYPE_DIR
        TSK_VS_PART_FLAG_ALLOC = pytsk3.TSK_VS_PART_FLAG_ALLOC
except ImportError as e:
    print(f"**치명적 오류**: dfvfs 관련 모듈 임포트 실패. 원인: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

if IS_MOCK_MODE:
    # (Mock 클래스 정의는 기존과 동일)
    print("경고: 필수 포렌식 라이브러리(pytsk3, dfvfs)가 설치되지 않았습니다. Mock 모드로 실행됩니다.")
    class MockDir:
        def __init__(self, name): self.name = name
        def GetSubFileEntries(self):
            if self.name == '\\': return ['Users']
            if self.name.upper() == 'USERS': return ['forensic', 'Default', '$Recycle.Bin']
            return []
        def GetSubFileEntry(self, name):
            if name.upper() in ['USERS', 'FORENSIC', 'DEFAULT', '$RECYCLE.BIN']: return MockFile(name=name, is_dir=True)
            if name.upper().endswith(('.PF', '.JSON', '.LOG', '.JSONL', 'CACHE_DATA')): return MockFile(name=name, is_file=True)
            return None
    class MockFile:
        def __init__(self, name, is_dir=False, is_file=True):
            self._is_dir, self._is_file, self._name = is_dir, is_file, name
        def IsDirectory(self): return self._is_dir
        def IsFile(self): return self._is_file
        def GetSize(self): return 1024
        def GetFileObject(self): return self
        def IsAllocated(self): return True
        def read(self, size): return f"Mock Data for {self._name}".encode('utf-8') if self._is_file else b''
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, exc_type, exc_val, exc_tb): pass
    TSK_FS_NAME_TYPE_REG, TSK_FS_NAME_TYPE_DIR, TSK_VS_PART_FLAG_ALLOC = 1, 2, 1

# --- LLM 모드 및 분류 정의 (기존과 동일) ---
MODE_MAP = {
    "api": ["CHATGPT", "CLAUDE"],
    "standalone": ["LMSTUDIO", "JAN"]
}

# --- LLM 아티팩트 경로 정의 (기존과 동일) ---
LLM_ARTIFACTS = {
    "CHATGPT": {
        "Program_Execution_Traces": [
            {"path": r"C:\Windows\Prefetch\CHATGPT*.pf", "extract_from": "Prefetch"},
        ],
        "User_Info+Prompt+File_Uploads": [
            {"path": r"C:\Users\*\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\Cache\Cache_Data", "extract_from": "Cache_Data"},
        ],
        "Network": [
            {"path": r"C:\Users\*\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\Network", "extract_files": ["Network Persistent State", "TransportSecurity", "Cookies"]},
        ],
    },
    "CLAUDE": {
        "Program_Execution_Traces": [
            {"path": r"C:\Windows\Prefetch\CLAUDE*.pf", "extract_from": "Prefetch"},
            {"path": r"C:\Users\*\AppData\Roaming\Claude\logs\main.log", "extract_from": "logs"},
            {"path": r"C:\Users\*\AppData\Roaming\Claude\logs\window.log", "extract_from": "logs"},
        ],
        "User_Info": [
            {"path": r"C:\Users\*\AppData\Roaming\Claude\Local Storage\leveldb", "extract_from": "leveldb"},
        ],
        "Prompt+File_Uploads": [
            {"path": r"C:\Users\*\AppData\Roaming\Claude\Cache\Cache_Data", "extract_from": "Cache_Data"},
            {"path": r"C:\Users\*\AppData\Roaming\Claude\Local Storage\leveldb", "extract_from": "leveldb"},
        ],
        "Network": [
            {"path": r"C:\Users\*\AppData\Roaming\Claude\Network", "extract_files": ["Network Persistent State", "TransportSecurity", "Cookies"]},
        ],
    },
    "LMSTUDIO": {
        "Program_Execution_Traces": [
            {"path": r"C:\Windows\Prefetch\LM STUDIO*.pf", "extract_from": "Prefetch"},
            {"path": r"C:\Users\*\AppData\Roaming\LM Studio\logs\main.log", "extract_from": "logs"},
        ],
        "User_Info": [
            {"path": r"C:\Users\*\AppData\Roaming\LM Studio\user-profile.json", "extract_from": "user-profile.json"},
        ],
        "Prompt": [
            {"path": r"C:\Users\*\.lmstudio\conversations\*.conversation.json", "extract_from": "conversations"},
        ],
        "File_Uploads": [
            {"path": r"C:\Users\*\.lmstudio\user-files", "extract_from": "user-files"},
        ],
        "Network": [
            {"path": r"C:\Users\*\.lmstudio\Network", "extract_files": ["Network Persistent State", "TransportSecurity", "Cookies"]},
        ],
    },
    "JAN": {
        "Program_Execution_Traces": [
            {"path": r"C:\Windows\Prefetch\JAN*.pf", "extract_from": "Prefetch"},
            {"path": r"C:\Users\*\AppData\Roaming\Jan\data\logs\app.log", "extract_from": "logs"},
        ],
        "Prompt": [
            {"path": r"C:\Users\*\AppData\Roaming\Jan\data\threads", "extract_from": "threads"},
        ],
    },
}
# --- dfVFS 기반 TSK 파일 시스템 탐색 및 추출 로직 (기존 함수 재사용) ---

def normalize_path(path):
    normalized = path.replace('\\', '/')
    if ':' in normalized and normalized.index(':') < normalized.index('/'):
        normalized = normalized.split(':', 1)[-1]
    return normalized.upper().lstrip('/')

def get_image_root_entry(image_path):
    if IS_MOCK_MODE: return MockDir(name='\\'), None
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
            print(f"오류: E01 이미지에서 파일 시스템 루트를 찾을 수 없습니다.", file=sys.stderr)
            return None, None
        return root_entry, fs_path_spec
    except Exception as e:
        print(f"오류: dfVFS를 이용한 이미지 처리 중 오류 발생: {e}", file=sys.stderr)
        return None, None

def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts, artifact_info, collected_paths):
    if not path_parts:
        extract_item(root_entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths)
        return

    current_part, remaining_parts = path_parts[0], path_parts[1:]
    is_directory = (hasattr(root_entry, 'IsDirectory') and root_entry.IsDirectory()) or (hasattr(root_entry, 'is_directory') and root_entry.is_directory)
    if not is_directory: return

    if current_part == '*':
        for sub_entry in root_entry._GetSubFileEntries():
            name_str = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
            if name_str in ['.', '..']: continue
            recursive_search_and_extract(sub_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, collected_paths)
    else:
        found_entries = []
        if '*' in current_part:
            pattern = re.compile(current_part.replace('.', r'\.').replace('*', '.*'), re.IGNORECASE)
            for entry in root_entry._GetSubFileEntries():
                file_name = entry.name.decode('utf-8', 'ignore') if isinstance(entry.name, bytes) else entry.name
                if pattern.match(file_name):
                    found_entries.append(entry)
        else:
            for entry in root_entry._GetSubFileEntries():
                file_name = entry.name.decode('utf-8', 'ignore') if isinstance(entry.name, bytes) else entry.name
                if file_name.upper() == current_part.upper():
                    found_entries.append(entry)
                    break
        for found_entry in found_entries:
            name_str = found_entry.name.decode('utf-8', 'ignore') if isinstance(found_entry.name, bytes) else found_entry.name
            recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, collected_paths)

# ✨ [수정됨] BackEndError 발생 시 프로그램을 중지하는 대신 경고를 출력하고 계속 진행하도록 수정
def extract_item(entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths):
    is_file = (hasattr(entry, 'IsFile') and entry.IsFile()) or (hasattr(entry, 'is_file') and entry.is_file)
    is_directory = (hasattr(entry, 'IsDirectory') and entry.IsDirectory()) or (hasattr(entry, 'is_directory') and entry.is_directory)
    original_full_path = '/' + '/'.join(current_path_parts)

    # 경로를 collected_paths 딕셔너리에 추가
    category_str = str(extract_category).replace('+', '_')
    if category_str not in collected_paths:
        collected_paths[category_str] = []
    
    # 중복된 경로가 추가되지 않도록 확인
    if original_full_path not in collected_paths[category_str]:
        collected_paths[category_str].append(original_full_path)

    # 특별 케이스: Network 폴더
    if "extract_files" in artifact_info and is_directory:
        target_files_upper = [f.upper() for f in artifact_info["extract_files"]]
        print(f"  [탐색] '{original_full_path}'에서 지정된 파일 추출: {', '.join(artifact_info['extract_files'])}")
        try:
            for sub_entry in entry._GetSubFileEntries():
                sub_name = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
                if sub_name.upper() in target_files_upper:
                    new_info = {"extract_from": sub_name}
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], new_info, collected_paths)
        except Exception as e:
            print(f"  [경고] 디렉터리 '{original_full_path}'의 하위 항목을 읽는 중 오류 발생: {e}", file=sys.stderr)
        return

    # 저장할 상대 경로 계산
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
    output_target = output_dir / extract_category / Path(*relative_path_parts)

    # 파일/디렉토리 추출 로직
    if is_file:
        output_target.parent.mkdir(parents=True, exist_ok=True)
        print(f"  [추출] 파일: {original_full_path} -> {output_target}")
        try:
            with open(output_target, 'wb') as outfile:
                file_object = entry.GetFileObject()
                if file_object:
                    chunk = file_object.read(1024 * 1024)
                    while chunk:
                        outfile.write(chunk)
                        chunk = file_object.read(1024 * 1024)
                    file_object.close()
        except Exception as e:
            print(f"  [오류] 파일 쓰기 실패 ({output_target}): {e}", file=sys.stderr)
    elif is_directory:
        print(f"  [추출] 디렉토리: {original_full_path} -> {output_target}")
        output_target.mkdir(parents=True, exist_ok=True)
        # ✨ [수정됨] 여기서 try...except 블록 추가
        try:
            for sub_entry in entry._GetSubFileEntries():
                sub_name = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
                if sub_name not in ['.', '..']:
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], artifact_info, collected_paths)
        except Exception as e:
            print(f"  [경고] 디렉터리 '{original_full_path}'의 하위 항목을 처리하는 중 오류 발생, 일부 파일을 건너뜁니다. 원인: {e}", file=sys.stderr)

def main():
    """메인 함수: 명령줄 인수를 파싱하고 추출 작업을 시작합니다."""

    # ✨ [수정됨] 'usage' 파라미터에서 중복되는 "usage: " 단어를 제거했습니다.
    parser = argparse.ArgumentParser(
        description="LLM Forensic Artifact Extraction Tool (dfVFS based for E01 support)",
        usage="%(prog)s <E01_IMAGE_PATH> <MODE> <LLM_NAME> <OUTPUT_DIR>",
        epilog="Example:\n  %(prog)s C:\\image.E01 api CHATGPT C:\\results",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("E01_IMAGE_PATH",
                        help="Path to the E01 image file to be analyzed")
    parser.add_argument("MODE",
                        choices=["api", "standalone"],
                        help="LLM operation mode")
    parser.add_argument("LLM_NAME",
                        choices=list(LLM_ARTIFACTS.keys()),
                        help="Name of the LLM program to extract artifacts from")
    parser.add_argument("OUTPUT_DIR",
                        help="Path to the output directory where artifacts will be saved")

    args = parser.parse_args()
    llm_name_upper = args.LLM_NAME.upper()

    # --- 유효성 검증 로직 (기존과 동일) ---
    if llm_name_upper not in MODE_MAP.get(args.MODE, []):
        print(f"\nError: '{args.LLM_NAME}' does not belong to the '{args.MODE}' mode.", file=sys.stderr)
        if args.MODE == 'api':
            print(f"Valid choices for 'api' mode are: {MODE_MAP['api']}", file=sys.stderr)
        else:
            print(f"Valid choices for 'standalone' mode are: {MODE_MAP['standalone']}", file=sys.stderr)
        sys.exit(1)

    if IS_MOCK_MODE:
        print("\n--- Execution failed: Running in Mock Mode due to library import errors. ---")
        return

    program_output_dir = Path(args.OUTPUT_DIR) / llm_name_upper
    program_output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Opening image file and mounting filesystem: {args.E01_IMAGE_PATH}")
    root_entry, _ = get_image_root_entry(Path(args.E01_IMAGE_PATH))
    if root_entry is None: return
    print("Filesystem root entry confirmed.")

    collected_paths = {}

    artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]
    for category, artifacts in artifacts_to_extract.items():
        print(f"\n--- Starting artifact extraction for category: {category} ---")
        for artifact_info in artifacts:
            full_path = artifact_info["path"]
            normalized = normalize_path(full_path)
            path_parts = normalized.split('/')
            if not path_parts or not path_parts[0]: continue
            print(f"Searching for pattern: {full_path}")
            recursive_search_and_extract(root_entry, path_parts, program_output_dir, Path(category.replace('+', '_')), [], artifact_info, collected_paths)

    path_log_file_path = program_output_dir / "extracted_paths.txt"
    with open(path_log_file_path, 'w', encoding='utf-8') as path_log_file:
        image_name = Path(args.E01_IMAGE_PATH).name
        path_log_file.write(f"--- LLM Forensic Artifacts Extracted Paths (Source Image: {image_name}) ---\n")
        
        for category, paths in sorted(collected_paths.items()):
            path_log_file.write(f"\n\n## {category.replace('_', '+')}\n")
            path_log_file.write("---\n")
            for path in sorted(paths):
                path_log_file.write(f"- {path}\n")

    print("\n--- All artifact extraction tasks are complete. ---")
    print(f"Results saved to: {program_output_dir.resolve()}")
    print(f"Extraction path log: {path_log_file_path.resolve()}")


if __name__ == "__main__":
    main()