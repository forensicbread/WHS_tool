import argparse
import os
import sys
import platform
import re
from pathlib import Path

# --- dfvfs 및 pytsk3 라이브러리 임포트 (문제 진단 코드 추가) ---
IS_MOCK_MODE = False

try:
    import pytsk3
except ImportError as e:
    # pytsk3 로딩 실패 시 Mock 모드 설정
    print(f"**치명적 오류**: pytsk3 임포트 실패. 원인: {e}", file=sys.stderr)
    IS_MOCK_MODE = True

try:
    # pytsk3 임포트 성공 시에만 dfvfs 임포트 시도
    if not IS_MOCK_MODE:
        import dfvfs.vfs.tsk_file_entry
        from dfvfs.resolver import context
        from dfvfs.lib import definitions
        # dfvfs.path.path_spec 클래스를 사용합니다.
        from dfvfs.path import path_spec as dfvfs_path_spec 
        from dfvfs.path import factory as path_spec_factory 
        from dfvfs.resolver import resolver as path_spec_resolver
        
        # pytsk3 상수 정의
        TSK_FS_NAME_TYPE_REG = pytsk3.TSK_FS_NAME_TYPE_REG
        TSK_FS_NAME_TYPE_DIR = pytsk3.TSK_FS_NAME_TYPE_DIR
        TSK_VS_PART_FLAG_ALLOC = pytsk3.TSK_VS_PART_FLAG_ALLOC
except ImportError as e:
    # dfvfs 로딩 실패 시 Mock 모드 설정
    print(f"**치명적 오류**: dfvfs 관련 모듈 임포트 실패. 원인: {e}", file=sys.stderr)
    IS_MOCK_MODE = True


if IS_MOCK_MODE:
    # 라이브러리가 설치되지 않았거나 임포트 중 오류 발생 시 Mock 클래스 정의
    print("경고: 필수 포렌식 라이브러리(pytsk3, dfvfs)가 설치되지 않았습니다. Mock 모드로 실행됩니다.")
    print("실제 포렌식 이미지 분석을 위해서는 안내된 설치 지침을 따라주세요.")
    
    # --- Mock Implementation ---
    class MockDir:
        def __init__(self, name): self.name = name
        def GetSubFileEntries(self):
            if self.name == '\\': return ['Users']
            if self.name.upper() == 'USERS': return ['forensic', 'Default', '$Recycle.Bin']
            return []
            
        def GetSubFileEntry(self, name):
            if name.upper() in ['USERS', 'FORENSIC', 'DEFAULT', '$RECYCLE.BIN']:
                return MockFile(name=name, is_dir=True)
            if name.upper().endswith(('.PF', '.JSON', '.LOG', '.JSONL', 'CACHE_DATA')):
                return MockFile(name=name, is_file=True)
            return None

    class MockFile:
        def __init__(self, name, is_dir=False, is_file=True):
            self._is_dir = is_dir
            self._is_file = is_file
            self._name = name
        def IsDirectory(self): return self._is_dir
        def IsFile(self): return self._is_file
        def GetSize(self): return 1024
        def GetFileObject(self): return self 
        def IsAllocated(self): return True 
        def read(self, size): 
            return f"Mock Data for {self._name}".encode('utf-8') if self._is_file else b''
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, exc_type, exc_val, exc_tb): pass

    # Mock 객체로 대체
    TSK_FS_NAME_TYPE_REG = 1
    TSK_FS_NAME_TYPE_DIR = 2
    TSK_VS_PART_FLAG_ALLOC = 1
    
# --- LLM 모드 및 분류 정의 (대문자로 통일) ---
MODE_MAP = {
    "api": ["CHATGPT", "CLAUDE"],
    "standalone": ["LMSTUDIO", "JAN"]
}

# --- LLM 아티팩트 경로 정의 (Windows 환경 기준, 키는 대문자로 통일) ---
LLM_ARTIFACTS = {
    "LMSTUDIO": { 
        "Program_Execution_Traces": [
            r"C:\Windows\Prefetch\LMSTUDIO*.pf",
            r"C:\Users\*\AppData\Roaming\LM Studio\logs\main.log",
        ],
        "User_Info": [
            r"C:\Users\*\AppData\Roaming\LM Studio\user-profile.json",
        ],
        "Prompt_History": [
            r"C:\Users\*\.lmstudio\conversations\*.conversation.json",
        ],
        "File_Uploads": [
            r"C:\Users\*\.lmstudio\user-files", # 디렉토리 통째로 추출
        ],
    },
    "JAN": {
        "Program_Execution_Traces": [
            r"C:\Windows\Prefetch\JAN*.pf",
            r"C:\Users\*\AppData\Roaming\Jan\logs\app.log",
        ],
        "Prompt_History": [
            r"C:\Users\*\AppData\Roaming\Jan\data\threads\thread.json",
            r"C:\Users\*\AppData\Roaming\Jan\data\threads\messages.jsonl",
        ],
    },
    "CHATGPT": { 
        "User_Info_Prompt_Cache": [
            r"C:\Users\*\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\Cache\Cache_Data", # 캐시 데이터 폴더 전체
        ],
        "Network_Info": [
            r"C:\Users\*\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_*\LocalCache\Roaming\ChatGPT\Network", # 네트워크 정보 폴더 전체
        ],
        "Program_Execution_Traces": [
            r"C:\Windows\Prefetch\CHATGPT*.pf",
        ],
    },
    "CLAUDE": { 
        "Program_Execution_Traces": [
            r"C:\Windows\Prefetch\CLAUDE*.pf",
            r"C:\Users\*\AppData\Roaming\Claude\logs\main.log",
            r"C:\Users\*\AppData\Roaming\Claude\logs\window.log",
        ],
        "User_Info": [
            r"C:\Users\*\AppData\Roaming\Claude\Local Storage\leveldb", # LevelDB 폴더 전체
        ],
        "Prompt_History": [
            r"C:\Users\*\AppData\Roaming\Claude\Cache\Cache_Data", # 캐시 데이터 폴더 전체
        ],
        "Network_Info": [
            r"C:\Users\*\AppData\Roaming\Claude\Network", # 네트워크 정보 폴더 전체
        ],
    },
}

# --- dfVFS 기반 TSK 파일 시스템 탐색 및 추출 로직 ---

def normalize_path(path):
    """Windows 경로를 TSK 탐색을 위해 정규화합니다. (C: 제거, 슬래시 통일, 대문자 변환)"""
    normalized = path.replace('\\', '/')
    if ':' in normalized and normalized.index(':') < normalized.index('/'):
        normalized = normalized.split(':', 1)[-1]
    return normalized.upper().lstrip('/')


def get_image_root_entry(image_path):
    """dfVFS를 사용하여 E01 이미지의 NTFS 파일 시스템 루트 엔트리를 가져옵니다."""
    if IS_MOCK_MODE:
        return MockDir(name='\\'), None

    try:
        # 1. OS 경로 지정
        os_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_OS, location=str(image_path))
        
        # 2. EWF 이미지 레이어 추가
        ewf_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_EWF, parent=os_path_spec)
            
        # 3. 파티션 지정: 세 번째(/p3) 파티션을 지정합니다.
        volume_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_TSK_PARTITION, location='/p3', parent=ewf_path_spec)
            
        # 4. 파일 시스템 지정
        fs_path_spec = path_spec_factory.Factory.NewPathSpec(
            definitions.TYPE_INDICATOR_NTFS, location='/', parent=volume_path_spec)

        # Resolver 객체를 생성한 후 OpenFileEntry 함수를 호출합니다.
        resolver = path_spec_resolver.Resolver()
        root_entry = resolver.OpenFileEntry(fs_path_spec)
        
        if not root_entry:
             # 파티션 테이블이 없는 경우를 대비해 파티션 레이어를 건너뛰고 재시도합니다.
            fs_path_spec_raw = path_spec_factory.Factory.NewPathSpec(
                definitions.TYPE_INDICATOR_NTFS, location='/', parent=ewf_path_spec)
            root_entry = resolver.OpenFileEntry(fs_path_spec_raw)
            
        if not root_entry:
            print(f"오류: E01 이미지에서 파일 시스템 루트를 찾을 수 없습니다. 파티션 구조를 확인하세요.", file=sys.stderr)
            return None, None

        return root_entry, fs_path_spec

    except Exception as e:
        print(f"오류: dfVFS를 이용한 이미지 처리 중 오류 발생: {e}", file=sys.stderr)
        return None, None

def recursive_search_and_extract(root_entry, path_parts, output_dir, extract_category, current_path_parts):
    """
    dfvfs File Entry 객체를 사용하여 파일 시스템 내에서 주어진 경로 패턴을 재귀적으로 검색하고 추출합니다. (수정된 최종 버전)
    """
    # 디버깅을 위한 현재 탐색 상태 출력
    print(f"[탐색] 현재: {'/'.join(current_path_parts) or '/'}, 찾는 중: {path_parts[0] if path_parts else '파일/폴더 추출 단계'}")

    if not path_parts:
        # 경로의 끝에 도달: 파일/디렉토리 추출
        if hasattr(root_entry, 'IsFile') and root_entry.IsFile() or \
           (hasattr(root_entry, 'is_file') and root_entry.is_file):
            extract_item(root_entry, output_dir, extract_category, current_path_parts)
        # 디렉토리 자체를 통째로 추출해야 하는 경우 (예: /user-files)
        elif (hasattr(root_entry, 'IsDirectory') and root_entry.IsDirectory()) or \
             (hasattr(root_entry, 'is_directory') and root_entry.is_directory):
            extract_item(root_entry, output_dir, extract_category, current_path_parts)
        return

    current_part = path_parts[0]
    remaining_parts = path_parts[1:]

    # 현재 엔트리가 디렉토리인지 확인
    is_directory = (hasattr(root_entry, 'IsDirectory') and root_entry.IsDirectory()) or \
                   (hasattr(root_entry, 'is_directory') and root_entry.is_directory)

    if not is_directory:
        return # 디렉토리가 아니면 더 이상 하위 탐색 불가

    # 1. 디렉토리 와일드카드 (*) 처리
    if current_part == '*':
        for sub_entry in root_entry._GetSubFileEntries():
            if not sub_entry: continue

            name_str = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name
            if name_str in ['.', '..']: continue

            new_current_path_parts = current_path_parts + [name_str]
            recursive_search_and_extract(sub_entry, remaining_parts, output_dir, extract_category, new_current_path_parts)

    # 2. 파일명 와일드카드 또는 정확한 이름 매칭
    else:
        found_entries = []

        # 2-1. 파일명 와일드카드 처리 (예: CHATGPT*.pf)
        if '*' in current_part:
            pattern = re.compile(current_part.replace('.', r'\.').replace('*', '.*'), re.IGNORECASE)
            for entry in root_entry._GetSubFileEntries():
                file_name = entry.name.decode('utf-8', 'ignore') if isinstance(entry.name, bytes) else entry.name
                if pattern.match(file_name) and file_name not in ['.', '..']:
                    found_entries.append(entry)

        # 2-2. 정확한 이름 매칭 (예: Users)
        else:
            for entry in root_entry._GetSubFileEntries():
                file_name = entry.name.decode('utf-8', 'ignore') if isinstance(entry.name, bytes) else entry.name
                if file_name.upper() == current_part.upper():
                    found_entries.append(entry)
                    break

        # 찾은 모든 항목에 대해 재귀 호출
        for found_entry in found_entries:
            if found_entry:
                name_str = found_entry.name.decode('utf-8', 'ignore') if isinstance(found_entry.name, bytes) else found_entry.name
                new_current_path_parts = current_path_parts + [name_str]
                recursive_search_and_extract(found_entry, remaining_parts, output_dir, extract_category, new_current_path_parts)
            
            else:
                # 3. 정확한 이름 매칭 (강화된 디버깅 버전)
                print("  [DEBUG] 루트 폴더의 내용물 목록을 확인합니다...")
                try:
                    # 모든 하위 항목을 리스트로 먼저 받아옵니다.
                    sub_entries = list(root_entry._GetSubFileEntries())
                    print(f"  [DEBUG] 루트에서 {len(sub_entries)}개의 항목을 찾았습니다.")

                    for entry_name in sub_entries:
                        file_name_str = "[이름 확인 불가]"
                        try:
                            # 객체에서 이름 속성을 가져옵니다. bytes인지 str인지도 확인합니다.
                            raw_name = entry_name.name
                            file_name_str = repr(raw_name) # repr()은 b'' 나 '' 를 그대로 보여줍니다.

                            # 실제 비교를 위한 문자열 처리
                            compare_name = raw_name
                            if isinstance(compare_name, bytes):
                                compare_name = compare_name.decode('utf-8', 'ignore')

                            print(f"    - 확인 중인 항목: {file_name_str}")

                            # 대소문자 무시하고 비교
                            if compare_name.upper() == current_part.upper():
                                print(f"    ----> ★★★ 일치 항목 발견: {file_name_str} ★★★")
                                found_entries.append(entry_name)
                                break # 하나 찾으면 중단

                        except Exception as name_e:
                            print(f"    - [에러] 항목 처리 중 오류 발생: {name_e}")

                    if not found_entries:
                        print("  [DEBUG] 일치하는 항목을 찾지 못했습니다.")

                except Exception as e:
                    print(f"  [DEBUG] 심각한 오류: 하위 항목 목록을 가져오는 중 에러 발생 - {e}")
            
            # 찾은 엔트리들에 대해 재귀 호출
            for found_entry in found_entries:
                entry = found_entry

                # is_allocated 속성이 없는 객체를 대비해 hasattr 추가
                if entry: # entry가 존재하는지만 확인하도록 조건을 단순화합니다.
                    # !!핵심 수정!!: 객체에서 이름(문자열)을 추출하여 경로 리스트에 추가합니다.
                    name_str = found_entry.name.decode('utf-8', 'ignore') if isinstance(found_entry.name, bytes) else found_entry.name
                    new_current_path_parts = current_path_parts + [name_str]

                    recursive_search_and_extract(entry, remaining_parts, output_dir, extract_category, new_current_path_parts)

def extract_item(entry, output_dir, extract_category, current_path_parts):
    """dfVFS Entry 객체를 사용하여 찾은 파일 또는 디렉토리를 결과 디렉토리에 복사합니다. (수정된 최종 버전)"""

    relative_path = Path(*current_path_parts)
    output_target = output_dir / extract_category / relative_path

    # 견고한 타입 확인 로직
    is_file = (hasattr(entry, 'IsFile') and entry.IsFile()) or (hasattr(entry, 'is_file') and entry.is_file)
    is_directory = (hasattr(entry, 'IsDirectory') and entry.IsDirectory()) or (hasattr(entry, 'is_directory') and entry.is_directory)

    if is_file: # 파일인 경우
        output_target.parent.mkdir(parents=True, exist_ok=True)
        print(f"  [추출] 파일: {relative_path}")
        try:
            with open(output_target, 'wb') as outfile:
                file_object = entry.GetFileObject()
                if file_object:
                    chunk_size = 1024 * 1024 # 1MB
                    while True:
                        chunk = file_object.read(chunk_size)
                        if not chunk: break
                        outfile.write(chunk)
                    file_object.close()
        except Exception as e:
            print(f"  [오류] 파일 쓰기 실패 ({relative_path}): {e}", file=sys.stderr)

    elif is_directory: # 디렉토리인 경우
        print(f"  [추출] 디렉토리: {relative_path}")
        output_target.mkdir(parents=True, exist_ok=True)

        # --- 여기가 핵심 수정 부분입니다 ---
        for sub_entry in entry._GetSubFileEntries(): # sub_entry가 바로 파일/폴더 객체입니다.
            if not sub_entry:
                continue

            # 할당 여부를 확인합니다.
            is_allocated = hasattr(sub_entry, 'is_allocated') and sub_entry.is_allocated

            # 객체에서 이름(문자열)을 추출합니다.
            name_str = ""
            if hasattr(sub_entry, 'name') and sub_entry.name is not None:
                name_str = sub_entry.name.decode('utf-8', 'ignore') if isinstance(sub_entry.name, bytes) else sub_entry.name

            # '.' 와 '..' 폴더는 건너뛰고 재귀 호출을 합니다.
            if name_str not in ['.', '..']:
                new_current_path_parts = current_path_parts + [name_str]
                extract_item(sub_entry, output_dir, extract_category, new_current_path_parts)

def main():
    """메인 함수: 명령줄 인수를 파싱하고 추출 작업을 시작합니다."""
    
    parser = argparse.ArgumentParser(description="LLM 포렌식 아티팩트 추출 도구 (dfVFS 기반 E01 지원)")
    parser.add_argument("E01_IMAGE_PATH", help="분석할 E01 이미지 파일 경로")
    parser.add_argument("MODE", choices=["api", "standalone"], help="LLM 작동 방식 (api: CHATGPT, CLAUDE / standalone: LMSTUDIO, JAN)")
    
    # LLM_ARTIFACTS의 키(대문자)를 choices로 사용
    parser.add_argument("LLM_NAME", choices=list(LLM_ARTIFACTS.keys()), help="추출할 LLM 프로그램 이름 (JAN, LMSTUDIO, CHATGPT, CLAUDE)")
    
    parser.add_argument("OUTPUT_DIR", help="추출된 파일이 저장될 결과 폴더 경로")

    args = parser.parse_args()
    
    llm_name_upper = args.LLM_NAME.upper()

    # --- 유효성 검증 로직: MODE와 LLM_NAME이 일치하는지 확인 (대문자 기준) ---
    if llm_name_upper not in MODE_MAP.get(args.MODE, []):
        print(f"\n오류: '{args.LLM_NAME}'은(는) '{args.MODE}' 작동 방식에 속하지 않습니다.", file=sys.stderr)
        if args.MODE == 'api':
            valid_llms = [name.capitalize() for name in MODE_MAP['api']]
            print(f"API 기반 LLM은 {valid_llms} 중 하나를 선택해야 합니다.", file=sys.stderr)
        else:
            valid_llms = [name.replace('STUDIO', ' Studio') for name in MODE_MAP['standalone']]
            print(f"독립 실행형 LLM은 {valid_llms} 중 하나를 선택해야 합니다.", file=sys.stderr)
        sys.exit(1)
    # -----------------------------------------------------------------

    if IS_MOCK_MODE:
        # 이전에 출력된 ImportError 메시지를 다시 출력합니다.
        print("\n--- 실제 분석 실패: 라이브러리 임포트 오류로 인해 Mock 모드로 실행됩니다. ---")
        print("이 문제는 dfvfs 버전 불일치로 인해 임포트 경로가 잘못되었거나, C 라이브러리를 찾지 못해 발생합니다.")
        print("----------------------------------------------------------------------\n")
        return


    # 결과 폴더 생성
    output_root = Path(args.OUTPUT_DIR)
    output_root.mkdir(parents=True, exist_ok=True)
    
    # 이미지 열기 및 루트 엔트리 가져오기 (dfVFS 사용)
    print(f"이미지 파일 열기 및 파일 시스템 마운트: {args.E01_IMAGE_PATH}")
    root_entry, fs_path_spec = get_image_root_entry(Path(args.E01_IMAGE_PATH))
    if root_entry is None:
        return
        
    print(f"파일 시스템 루트 엔트리 확인됨.")


    # 추출 대상 아티팩트 목록 가져오기 (대문자로 통일된 키 사용)
    artifacts_to_extract = LLM_ARTIFACTS[llm_name_upper]
    
    # 아티팩트 유형별로 추출 시작
    for category, paths in artifacts_to_extract.items():
        print(f"\n--- 아티팩트 카테고리 추출 시작: {category} ---")
        
        for full_path in paths:
            
            normalized = normalize_path(full_path)
            path_parts = normalized.split('/')
            if not path_parts or not path_parts[0]: continue

            print(f"탐색 패턴: {full_path}")
            
            recursive_search_and_extract(root_entry, path_parts, output_root, Path(category), [])
            
    print("\n--- 모든 아티팩트 추출 작업 완료 ---")
    print(f"결과 저장 경로: {output_root}")


if __name__ == "__main__":
    main()
