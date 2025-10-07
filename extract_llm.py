# LLM Forensic Artifact Extraction Tool
#
# 지정된 E01 포렌식 이미지에서 LLM(Large Language Model) 애플리케이션의 아티팩트를 추출한다.
# dfVFS 라이브러리를 사용하여 파일 시스템에 접근하고, 정의된 경로 패턴에 따라 파일을 검색 및 복사한다.

import argparse
import os
import sys
import platform
import re
from pathlib import Path

# --- 포렌식 라이브러리 임포트 ---
IS_MOCK_MODE = False

try:
    import pytsk3
except ImportError as e:
    print(f"**FATAL ERROR**: Failed to import pytsk3. Reason: {e}", file=sys.stderr)
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
    print(f"**FATAL ERROR**: Failed to import dfvfs modules. Reason: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

# --- 라이브러리 로딩 실패 시 Mock 모드 설정 ---
if IS_MOCK_MODE:
    print("Warning: Required forensic libraries (pytsk3, dfvfs) are not installed. Running in Mock Mode.")
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

# --- 전역 변수 및 설정 정의 ---
# LLM 애플리케이션의 작동 방식 분류
MODE_MAP = {
    "api": ["CHATGPT", "CLAUDE"],
    "standalone": ["LMSTUDIO", "JAN"]
}

# LLM 애플리케이션별 아티팩트 경로 및 추출 규칙 정의
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

# --- 헬퍼 함수 ---

def normalize_path(path):
    """Windows 경로를 TSK/dfVFS에서 사용 가능한 형식으로 변환한다."""
    normalized = path.replace('\\', '/')
    if ':' in normalized and normalized.index(':') < normalized.index('/'):
        normalized = normalized.split(':', 1)[-1]
    return normalized.upper().lstrip('/')

def get_image_root_entry(image_path):
    """dfVFS를 사용하여 E01 이미지의 파일 시스템 루트(root)에 접근한다."""
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
            print(f"Error: Could not find filesystem root in the E01 image.", file=sys.stderr)
            return None, None
        return root_entry, fs_path_spec
    except Exception as e:
        print(f"Error: An error occurred during image processing with dfVFS: {e}", file=sys.stderr)
        return None, None

# --- 아티팩트 탐색 및 추출 함수 ---

def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter):
    """정의된 경로 패턴을 따라 파일 시스템을 재귀적으로 탐색한다."""
    if not path_parts:
        extract_item(root_entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter)
        return

    current_part, remaining_parts = path_parts[0], path_parts[1:]
    is_directory = (hasattr(root_entry, 'IsDirectory') and root_entry.IsDirectory()) or (hasattr(root_entry, 'is_directory') and root_entry.is_directory)
    if not is_directory: return

    # 와일드카드('*') 처리 또는 정확한 이름 매칭
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
            recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, collected_paths, counter)

def extract_item(entry, output_dir, extract_category, current_path_parts, artifact_info, collected_paths, counter):
    """
    발견된 파일/디렉터리를 결과 폴더에 복사하고, 추출된 개수를 세고, 로그를 위해 경로를 수집한다.
    """
    is_file = (hasattr(entry, 'IsFile') and entry.IsFile()) or (hasattr(entry, 'is_file') and entry.is_file)
    is_directory = (hasattr(entry, 'IsDirectory') and entry.IsDirectory()) or (hasattr(entry, 'is_directory') and entry.is_directory)
    original_full_path = '/' + '/'.join(current_path_parts)

    # 로그 파일용 경로 수집
    category_str = str(extract_category).replace('+', '_')
    if category_str not in collected_paths:
        collected_paths[category_str] = []
    if original_full_path not in collected_paths[category_str]:
        collected_paths[category_str].append(original_full_path)

    # 'Network' 폴더와 같이 특정 파일만 추출해야 하는 경우의 특별 로직
    if "extract_files" in artifact_info and is_directory:
        target_files_upper = [f.upper() for f in artifact_info["extract_files"]]
        try:
            for sub_entry in entry._GetSubFileEntries():
                sub_name = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
                if sub_name.upper() in target_files_upper:
                    new_info = {"extract_from": sub_name}
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], new_info, collected_paths, counter)
        except Exception as e:
            pass # 손상된 파일 등으로 오류 발생 시 무시하고 계속 진행
        return

    # 결과 폴더에 저장될 상대 경로 계산
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

    # 파일 또는 디렉터리 추출 및 카운터 증가
    if is_file:
        counter['count'] += 1
        output_target.parent.mkdir(parents=True, exist_ok=True)
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
            pass
    elif is_directory:
        counter['count'] += 1
        output_target.mkdir(parents=True, exist_ok=True)
        try:
            for sub_entry in entry._GetSubFileEntries():
                sub_name = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
                if sub_name not in ['.', '..']:
                    extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], artifact_info, collected_paths, counter)
        except Exception as e:
            pass

# --- 메인 실행 함수 ---

def main():
    """스크립트의 메인 실행 함수. 인자 파싱부터 추출, 결과 출력까지 전체 과정을 제어한다."""
    
    # --- 1. 명령줄 인자 파싱 및 도움말 설정 ---
    parser = argparse.ArgumentParser(
        description="LLM Forensic Artifact Extraction Tool (dfVFS based for E01 support)",
        usage="%(prog)s <E01_IMAGE_PATH> <MODE> <LLM_NAME> <OUTPUT_DIR>",
        epilog="Example:\n  %(prog)s C:\\image.E01 api CHATGPT C:\\results",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("E01_IMAGE_PATH", help="Path to the E01 image file to be analyzed")
    parser.add_argument("MODE", choices=["api", "standalone"], help="LLM operation mode")
    parser.add_argument("LLM_NAME", choices=list(LLM_ARTIFACTS.keys()), help="Name of the LLM program to extract artifacts from")
    parser.add_argument("OUTPUT_DIR", help="Path to the output directory where artifacts will be saved")

    args = parser.parse_args()
    llm_name_upper = args.LLM_NAME.upper()

    # --- 2. 인자 유효성 검증 ---
    if llm_name_upper not in MODE_MAP.get(args.MODE, []):
        print(f"\nError: '{args.LLM_NAME}' does not belong to the '{args.MODE}' mode.", file=sys.stderr)
        sys.exit(1)
    if IS_MOCK_MODE:
        print("\n--- Execution failed: Running in Mock Mode due to library import errors. ---")
        return

    # --- 3. 이미지 마운트 및 준비 ---
    program_output_dir = Path(args.OUTPUT_DIR) / llm_name_upper
    program_output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Opening image file and mounting filesystem: {args.E01_IMAGE_PATH}")
    root_entry, _ = get_image_root_entry(Path(args.E01_IMAGE_PATH))
    if root_entry is None: return
    print("Filesystem root entry confirmed.")

    # 추출된 아티팩트의 전체 경로를 저장할 딕셔너리
    collected_paths = {}

    # --- 4. 아티팩트 추출 시작 ---
    artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]
    for category, artifacts in artifacts_to_extract.items():
        print(f"\n--- Starting artifact extraction for category: {category} ---")
        for artifact_info in artifacts:
            full_path = artifact_info["path"]
            normalized = normalize_path(full_path)
            path_parts = normalized.split('/')
            if not path_parts or not path_parts[0]: continue
            
            print(f"Searching for pattern: {full_path}")
            # 각 패턴을 탐색하기 전에 카운터를 초기화
            counter = {'count': 0}
            # 재귀 탐색 및 추출 함수 호출
            recursive_search_and_extract(root_entry, path_parts, program_output_dir, Path(category.replace('+', '_')), [], artifact_info, collected_paths, counter)
            
            # 탐색 완료 후 요약 메시지 출력
            count = counter['count']
            if count > 0:
                print(f"  -> Found and extracted {count} item(s).")
            else:
                print(f"  -> No items found.")

    # --- 5. 결과 로그 파일 생성 ---
    path_log_file_path = program_output_dir / "extracted_paths.txt"
    with open(path_log_file_path, 'w', encoding='utf-8') as path_log_file:
        image_name = Path(args.E01_IMAGE_PATH).name
        path_log_file.write(f"--- LLM Forensic Artifacts Extracted Paths (Source Image: {image_name}) ---\n")
        
        # 카테고리별로 정렬하여 로그 작성
        for category, paths in sorted(collected_paths.items()):
            path_log_file.write(f"\n\n## {category.replace('_', '+')}\n")
            path_log_file.write("---\n")
            # 각 카테고리 내의 경로들도 정렬하여 일관성 유지
            for path in sorted(paths):
                path_log_file.write(f"- {path}\n")

    # --- 6. 최종 결과 출력 ---
    print("\n--- All artifact extraction tasks are complete. ---")
    print(f"Results saved to: {program_output_dir.resolve()}")
    print(f"Extraction path log: {path_log_file_path.resolve()}")


if __name__ == "__main__":
    main()