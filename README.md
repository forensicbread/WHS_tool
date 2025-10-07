# WHS_tool – LLM 포렌식 아티팩트 추출 도구

이 도구는 **E01 포렌식 이미지**에서 **LLM(예: ChatGPT, Claude, LM Studio, Jan)** 애플리케이션의 **실행 흔적 / 사용자 정보 / 프롬프트 / 파일 업로드 / 네트워크 아티팩트**를 자동으로 찾아 **결과 폴더로 복사**합니다.  
dfVFS를 통해 E01 이미지를 읽고, 앱별로 정의된 경로 패턴을 재귀적으로 수집합니다.

---

## 지원 대상

- **MODE=api**: `CHATGPT`, `CLAUDE`  
- **MODE=standalone**: `LMSTUDIO`, `JAN`

> 프로그램별 세부 경로 패턴은 `extract_llm.py` 상단 정의를 참고하세요.

---

## 요구 사항

- **Python**: 3.9 이상
- **Python 패키지(필수)**:
  - `dfvfs`, `pytsk3`, `libewf-python`, `rich`, `click`
- **네이티브 라이브러리**
  - **Ubuntu/WSL**: `libtsk-dev`, `libewf-dev`, `libbde-dev`, `libfsntfs-dev`, `build-essential`, `python3-dev`
  - **macOS(Homebrew)**: `sleuthkit`, `libewf`, `pkg-config`
  - **Windows**: WSL(우분투) 사용 권장

---

## 설치/실행 – Windows (WSL 권장)

```bash
# 1) (PowerShell 관리자) WSL 설치
wsl --install -d Ubuntu

# 2) (WSL Ubuntu) 네이티브 라이브러리 설치
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential   libtsk-dev libewf-dev libbde-dev libfsntfs-dev

# 3) 가상환경 생성 및 활성화 (예: whs-windows)
mkdir -p ~/venvs
python3 -m venv --prompt whs-windows ~/venvs/whs-windows
source ~/venvs/whs-windows/bin/activate

# 4) 프로젝트 경로로 이동 후 의존성 설치
#    ➤ 자신의 WHS_tool 경로를 직접 넣어 주세요 (<> 부분 교체)
cd "<YOUR_PATH_TO_WHS_tool>"
#    예시(WSL에서 C: 드라이브 접근): cd "/mnt/c/Users/jimin/Desktop/WHS_tool"
#    예시(WSL 홈에 복사해둔 경우):   cd "$HOME/WHS_tool"

python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# 5) 실행 예시 (CHATGPT)
python extract_llm.py ./E01/CHATGPT.E01 api CHATGPT ./result
```

> 팁: 가상환경은 WSL 홈(`~/venvs`)에 두고, 소스/E01은 `/mnt/c/...`로 접근하면 경로/권한 이슈가 줄어듭니다.

---

## 설치/실행 – macOS

```bash
# 1) 필수 도구(선택): Xcode Command Line Tools
xcode-select --install

# 2) (선택) Homebrew로 네이티브 라이브러리 설치
brew update
brew install sleuthkit libewf pkg-config

# 3) 가상환경 생성 및 활성화 (예: whs-macos)
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

## 사용법(Help)

도구의 전체 사용법은 `-h`, `--help`로 확인할 수 있습니다.

```bash
python extract_llm.py --help
```

예시 출력:

```
usage: extract_llm.py <E01_IMAGE_PATH> <MODE> <LLM_NAME> <OUTPUT_DIR>

LLM Forensic Artifact Extraction Tool (dfVFS based for E01 support)

positional arguments:
  E01_IMAGE_PATH        Path to the E01 image file to be analyzed
  {api,standalone}      LLM operation mode
  {CHATGPT,CLAUDE,LMSTUDIO,JAN}
                        Name of the LLM program to extract artifacts from
  OUTPUT_DIR            Path to the output directory where artifacts will be saved

options:
  -h, --help            show this help message and exit

Example:
  extract_llm.py C:\image.E01 api CHATGPT C:\results
```

---

## CLI 요약

```bash
python extract_llm.py <E01_IMAGE_PATH> <MODE> <LLM_NAME> <OUTPUT_DIR>

# 실행 예시
python extract_llm.py ./E01/CHATGPT.E01 api CHATGPT ./result
```

- `MODE`: `api` 또는 `standalone`
- `LLM_NAME`: `CHATGPT` | `CLAUDE` | `LMSTUDIO` | `JAN`
- `OUTPUT_DIR`: 결과 저장 폴더(없으면 자동 생성)

---

## 결과물

- `./result/<LLM_NAME>/<카테고리>/...` : 추출된 파일/디렉터리  
- `./result/<LLM_NAME>/extracted_paths.txt` : 이미지 내부 **발견·추출 경로 로그**

---

## 가상환경 종료(비활성화)

작업 종료 후 가상환경을 끄려면:

```bash
deactivate
```
