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

# --- ✨ [수정됨] LLM 아티팩트 경로에 추출 규칙 추가 ---
# 각 경로를 단순 문자열에서 "path"와 "extract_from" 또는 "extract_files"를 포함하는 딕셔너리로 변경
LLM_ARTIFACTS = {
    "LMSTUDIO": {
        "Program_Execution_Traces": [
            {"path": r"C:\Windows\Prefetch\LMSTUDIO*.pf", "extract_from": "Prefetch"},
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
    },
    "JAN": {
        "Program_Execution_Traces": [
            {"path": r"C:\Windows\Prefetch\JAN*.pf", "extract_from": "Prefetch"},
            {"path": r"C:\Users\*\AppData\Roaming\Jan\logs\app.log", "extract_from": "logs"},
        ],
        "Prompt": [
            {"path": r"C:\Users\*\AppData\Roaming\Jan\data\threads\thread.json", "extract_from": "threads"},
            {"path": r"C:\Users\*\AppData\Roaming\Jan\data\threads\messages.jsonl", "extract_from": "threads"},
        ],
    },
    "CHATGPT": {
        "User_Info_Prompt_File_Uploads": [
            {"path": r"C:\Users\*\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\Cache\Cache_Data", "extract_from": "Cache_Data"},
        ],
        "Network": [
            {"path": r"C:\Users\*\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\Network", "extract_files": ["Network Persistent State", "TransportSecurity", "Cookies"]},
        ],
        "Program_Execution_Traces": [
            {"path": r"C:\Windows\Prefetch\CHATGPT*.pf", "extract_from": "Prefetch"},
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
        "Prompt": [
            {"path": r"C:\Users\*\AppData\Roaming\Claude\Cache\Cache_Data", "extract_from": "Cache_Data"},
        ],
        "Network": [
            {"path": r"C:\Users\*\AppData\Roaming\Claude\Network", "extract_files": ["Network Persistent State", "TransportSecurity", "Cookies"]},
        ],
    },
}

# --- dfVFS 기반 TSK 파일 시스템 탐색 및 추출 로직 (기존과 동일) ---

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
            print(f"오류: E01 이미지에서 파일 시스템 루트를 찾을 수 없습니다. 파티션 구조를 확인하세요.", file=sys.stderr)
            return None, None
        return root_entry, fs_path_spec
    except Exception as e:
        print(f"오류: dfVFS를 이용한 이미지 처리 중 오류 발생: {e}", file=sys.stderr)
        return None, None

# ✨ [수정됨] 함수 시그니처에 artifact_info와 path_log_file 추가
def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts, artifact_info, path_log_file):
    """기존 검색 로직을 유지하되, 추가 인자를 하위 함수로 전달합니다."""
    if not path_parts:
        # ✨ [수정됨] 추가 인자를 extract_item으로 전달
        extract_item(root_entry, output_dir, extract_category, current_path_parts, artifact_info, path_log_file)
        return

    current_part, remaining_parts = path_parts[0], path_parts[1:]
    is_directory = (hasattr(root_entry, 'IsDirectory') and root_entry.IsDirectory()) or (hasattr(root_entry, 'is_directory') and root_entry.is_directory)
    if not is_directory: return

    if current_part == '*':
        for sub_entry in root_entry._GetSubFileEntries():
            name_str = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
            if name_str in ['.', '..']: continue
            # ✨ [수정됨] 재귀 호출 시 추가 인자 전달
            recursive_search_and_extract(sub_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, path_log_file)
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
            # ✨ [수정됨] 재귀 호출 시 추가 인자 전달
            recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, current_path_parts + [name_str], artifact_info, path_log_file)

# ✨ [수정됨] 추출 및 로깅 로직을 반영하여 함수 재작성
def extract_item(entry, output_dir, extract_category, current_path_parts, artifact_info, path_log_file):
    """찾은 파일/디렉토리를 새 규칙에 따라 복사하고 경로를 txt 파일에 로깅합니다."""
    is_file = (hasattr(entry, 'IsFile') and entry.IsFile()) or (hasattr(entry, 'is_file') and entry.is_file)
    is_directory = (hasattr(entry, 'IsDirectory') and entry.IsDirectory()) or (hasattr(entry, 'is_directory') and entry.is_directory)
    original_full_path = '/' + '/'.join(current_path_parts)

    # 특별 케이스: Network 폴더에서 특정 파일만 추출
    if "extract_files" in artifact_info and is_directory:
        target_files_upper = [f.upper() for f in artifact_info["extract_files"]]
        print(f"  [탐색] '{original_full_path}'에서 지정된 파일 추출: {', '.join(artifact_info['extract_files'])}")
        for sub_entry in entry._GetSubFileEntries():
            sub_name = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
            if sub_name.upper() in target_files_upper:
                # 찾은 파일에 대해 일반 추출 로직을 타도록 새 artifact_info를 만들어 재귀 호출
                new_info = {"extract_from": sub_name}
                extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], new_info, path_log_file)
        return # 이 디렉토리 자체나 다른 파일은 처리하지 않고 종료

    # 저장할 상대 경로 계산
    relative_path_parts = []
    extract_root_name = artifact_info.get("extract_from", "").upper().replace('\\', '/').split('/')[-1]
    if extract_root_name:
        upper_path_parts = [p.upper() for p in current_path_parts]
        try:
            start_index = upper_path_parts.index(extract_root_name)
            relative_path_parts = current_path_parts[start_index:]
        except ValueError:
            relative_path_parts = [current_path_parts[-1]] # 못 찾으면 파일명만
    else: # extract_from 규칙이 없는 경우 (extract_files 재귀 등)
        relative_path_parts = [current_path_parts[-1]]

    output_target = output_dir / extract_category / Path(*relative_path_parts)
    
    # 로그 파일에 원본 경로 기록
    path_log_file.write(f"카테고리: {extract_category}\n - 원본 경로: {original_full_path}\n\n")

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
        for sub_entry in entry._GetSubFileEntries():
            sub_name = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
            if sub_name not in ['.', '..']:
                extract_item(sub_entry, output_dir, extract_category, current_path_parts + [sub_name], artifact_info, path_log_file)

def main():
    """메인 함수: 명령줄 인수를 파싱하고 추출 작업을 시작합니다."""
    parser = argparse.ArgumentParser(description="LLM 포렌식 아티팩트 추출 도구 (dfVFS 기반 E01 지원)")
    parser.add_argument("E01_IMAGE_PATH", help="분석할 E01 이미지 파일 경로")
    parser.add_argument("MODE", choices=["api", "standalone"], help="LLM 작동 방식 (api: CHATGPT, CLAUDE / standalone: LMSTUDIO, JAN)")
    parser.add_argument("LLM_NAME", choices=list(LLM_ARTIFACTS.keys()), help="추출할 LLM 프로그램 이름 (JAN, LMSTUDIO, CHATGPT, CLAUDE)")
    parser.add_argument("OUTPUT_DIR", help="추출된 파일이 저장될 결과 폴더 경로")
    args = parser.parse_args()
    llm_name_upper = args.LLM_NAME.upper()

    if llm_name_upper not in MODE_MAP.get(args.MODE, []):
        # (유효성 검증 로직은 기존과 동일)
        print(f"\n오류: '{args.LLM_NAME}'은(는) '{args.MODE}' 작동 방식에 속하지 않습니다.", file=sys.stderr)
        sys.exit(1)

    if IS_MOCK_MODE:
        # (Mock 모드 설명은 기존과 동일)
        print("\n--- 실제 분석 실패: 라이브러리 임포트 오류로 인해 Mock 모드로 실행됩니다. ---")
        return

    output_root = Path(args.OUTPUT_DIR)
    output_root.mkdir(parents=True, exist_ok=True)
    
    print(f"이미지 파일 열기 및 파일 시스템 마운트: {args.E01_IMAGE_PATH}")
    root_entry, fs_path_spec = get_image_root_entry(Path(args.E01_IMAGE_PATH))
    if root_entry is None: return
    print(f"파일 시스템 루트 엔트리 확인됨.")

    # ✨ [수정됨] 로그 파일을 열고, 추출 루프를 with 블록 안으로 이동
    path_log_file_path = output_root / "extracted_paths.txt"
    with open(path_log_file_path, 'w', encoding='utf-8') as path_log_file:
        path_log_file.write(f"--- LLM Forensic Artifacts Extracted Paths ({args.E01_IMAGE_PATH}) ---\n\n")

        artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]
        for category, artifacts in artifacts_to_extract.items():
            print(f"\n--- 아티팩트 카테고리 추출 시작: {category} ---")
            
            # ✨ [수정됨] 새로운 딕셔너리 구조에 맞춰 루프 수정
            for artifact_info in artifacts:
                full_path = artifact_info["path"]
                normalized = normalize_path(full_path)
                path_parts = normalized.split('/')
                if not path_parts or not path_parts[0]: continue

                print(f"탐색 패턴: {full_path}")
                
                # ✨ [수정됨] artifact_info와 path_log_file 핸들 전달
                recursive_search_and_extract(root_entry, path_parts, output_root, Path(category), [], artifact_info, path_log_file)
            
    print("\n--- 모든 아티팩트 추출 작업 완료 ---")
    print(f"결과 저장 경로: {output_root.resolve()}")
    print(f"추출 경로 로그: {path_log_file_path.resolve()}")

if __name__ == "__main__":
    main()