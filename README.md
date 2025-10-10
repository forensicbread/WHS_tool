# WHS_tool – LLM 포렌식 아티팩트 추출 도구

이 도구는 **E01 포렌식 이미지**에서 **LLM(예: ChatGPT, Claude, LM Studio, Jan, 그 외 미정의 LLM)** 애플리케이션의 **실행 흔적 / 사용자 정보 / 프롬프트 / 파일 업로드 / 네트워크 아티팩트**를 자동으로 수집해 결과 폴더로 복사함.

dfVFS를 통해 E01 이미지를 읽고, 앱별로 정의된 경로 패턴 또는 휴리스틱 패턴을 재귀적으로 탐색함.


---

## 지원 대상

- **MODE = api**: `CHATGPT`, `CLAUDE`
- **MODE = standalone**: `LMSTUDIO`, `JAN`
- **그 외 LLM**: 위 2가지 모드 중 하나를 선택하여 **휴리스틱 모드**로 수집 가능

> 세부 경로 패턴은 `artifacts.json`을 참고.

---

## 요구 사항

- **Python**: 3.9 이상
- **Python 패키지(필수)**:
  - `dfvfs`, `pytsk3`, `libewf-python`, `rich`
- **네이티브 라이브러리**
  - **Ubuntu/WSL**: `libtsk-dev`, `libewf-dev`, `libbde-dev`, `libfsntfs-dev`, `build-essential`, `python3-dev`
  - **macOS(Homebrew)**: `sleuthkit`, `libewf`, `pkg-config`
  - **Windows**: WSL(우분투) 사용 권장

---

## 설치/실행 – Windows

### 방법 ① WSL‑Ubuntu **자동 설치 스크립트** — `setup_wsl.sh`
Windows에서 WSL과 필수 패키지를 한 번에 설치/셋업합니다.

```powershell
# PowerShell (관리자) — WSL 설치
wsl --install -d Ubuntu
# 설치/재부팅 후, "Ubuntu" 앱(WSL 터미널)을 실행

# (WSL) 리포지토리로 이동
cd "<YOUR_PATH_TO_WHS_tool>"

# (WSL) 스크립트 실행 (CRLF 이슈 대비)
sed -i 's/\r$//' setup_wsl.sh
bash ./setup_wsl.sh

# (WSL) 가상환경 활성화
source ~/venvs/whs-windows/bin/activate

# (WSL) 실행 (둘 중 택1)
python -m whs_tool "./E01/CLAUDE.E01" api CLAUDE "./result"
# 또는
python whs_tool/cli.py "./E01/CLAUDE.E01" api CLAUDE "./result"
```

스크립트가 수행하는 작업(요약):
- `python3-venv`, `python3-dev`, `build-essential` 설치
- `libtsk-dev`, `libewf-dev`, `libbde-dev`, `libfsntfs-dev` 등 포렌식 네이티브 라이브러리 설치
- 가상환경 생성/활성화 및 `requirements.txt` 설치
- 기본 동작 확인을 위한 간단 실행 테스트(옵션)

설치 후 실행 예시(WSL 터미널):
```bash
python extract_llm.py ./E01/CHATGPT.E01 api CHATGPT ./result
```

> 스크립트는 여러 번 실행해도 안전하도록 **idempotent**하게 작성합니다.

---

### 방법 ② WSL‑Ubuntu **수동 설치**
WSL을 직접 설치한 뒤, 필요한 패키지/가상환경을 수동으로 구성합니다.

```powershell
# PowerShell (관리자) — WSL 설치
wsl --install -d Ubuntu
# 설치/재부팅 후, "Ubuntu" 앱(WSL 터미널)을 실행
```

```bash
# (WSL) 네이티브 라이브러리 설치
sudo apt update
sudo apt install -y \
  python3-venv python3-dev build-essential \
  libtsk-dev libewf-dev libbde-dev libfsntfs-dev

# (WSL) 가상환경 생성/활성화
mkdir -p ~/venvs
python3 -m venv --prompt whs-windows ~/venvs/whs-windows
source ~/venvs/whs-windows/bin/activate

# (WSL) 의존성 설치
cd "/mnt/c/Users/<사용자명>/Desktop/논문/WHS_tool"   # 본인 경로로 수정
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# (WSL) 실행 (둘 중 택1)
python -m whs_tool "./E01/CHATGPT.E01" api CHATGPT "./result"
# 또는
python whs_tool/cli.py "./E01/CHATGPT.E01" api CHATGPT "./result"
```

> 팁: 소스/E01는 `/mnt/c/...` 경로로 접근하면 권한/경로 이슈를 줄일 수 있습니다.

---

## 설치/실행 – macOS

```bash
# 1) Xcode Command Line Tools(선택)
xcode-select --install

# 2) Homebrew(선택)로 네이티브 라이브러리 설치
brew update
brew install sleuthkit libewf pkg-config

# 3) 가상환경 생성 및 활성화
cd /path/to/WHS_tool
python3 -m venv --prompt whs-macos .venv-macos
source .venv-macos/bin/activate

# 4) 파이썬 의존성 설치
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 5) 실행 예시
python extract_llm.py ./E01/CHATGPT.E01 api CHATGPT ./result
```

---


## 사용법(Help) & 옵션

```bash
python extract_llm.py --help
```

### 기본 사용
```bash
python extract_llm.py <E01_IMAGE_PATH> <MODE> <LLM_NAME> <OUTPUT_DIR>
# 예시
python extract_llm.py ./E01/CHATGPT.E01 api CHATGPT ./result
```

- `MODE`: `api` | `standalone`
- `LLM_NAME`: `CHATGPT` | `CLAUDE` | `LMSTUDIO` | `JAN` | (그 외 임의 문자열 → 휴리스틱 모드)
- `OUTPUT_DIR`: 결과 저장 폴더(없으면 자동 생성)

### 출력 제어 옵션
- `--no-keep-plus` : 카테고리 폴더명에서 `+`를 `_`로 치환
- `--no-show-summary` : 마지막 **요약 테이블** 출력 생략
- `--no-final-summary` : 마지막 **영문 요약 메시지** 출력 생략

---

## 결과물

- `./result/<LLM_NAME>/<카테고리>/...` : 추출된 파일/디렉터리
- `./result/<LLM_NAME>/extraction_report.txt` : 이미지 내부 **발견·추출 경로/에러 로그**

---

## 동작 개요

1) **이미지 마운트 탐색**: E01 내 파티션(`/p1`…`/p10`)을 순회하며 NTFS + `Windows` 폴더 존재 파티션을 자동 탐지  
2) **경로 정규화 & 와일드카드 매칭**: `\`→`/` 변환, 대소문자 무시, `*` 패턴 처리  
3) **카테고리별 재귀 수집**: `Program_Execution_Traces`, `User_Info`, `Prompt(+File_Uploads)`, `Network` 등  
4) **부분 추출**: `extract_files` 지정 시 디렉터리 내 특정 파일(`Cookies`, `Network Persistent State` 등)만 선택 추출  
5) **로그/요약 출력**: 성공/실패를 분리하여 화면 및 `extraction_report.txt`에 기록


---
