# WHS_tool – LLM 포렌식 아티팩트 추출 도구

이 도구는 **E01 포렌식 이미지**에서 **LLM(예: ChatGPT, Claude, LM Studio, Jan)** 애플리케이션의 **실행 흔적/사용자 정보/프롬프트/업로드/네트워크 관련 아티팩트**를 자동으로 찾아 **결과 폴더로 복사**해 줍니다. <br>
내부적으로 dfVFS를 사용해 E01 파일의 파일시스템을 탐색하고, 프로그램별로 미리 정의된 경로 패턴에 따라 재귀적으로 수집합니다.

---

## 지원 대상(예시)

- **MODE=api**: `CHATGPT`, `CLAUDE`  
- **MODE=standalone**: `LMSTUDIO`, `JAN`

> 프로그램별 경로 패턴 및 카테고리는 `extract_llm.py` 상단 정의를 참고하세요.

---

## 요구 사항

Python 패키지(권장 고정 버전):

```
pytsk3==20250312
dfvfs==20240505
libewf-python==20240506
rich>=13.7
click>=8.1
```

> 운영체제 네이티브 라이브러리(리눅스/WSL): `libtsk-dev`, `libewf-dev`, `libbde-dev`, `libfsntfs-dev`, `build-essential`, `python3-dev` 등이 필요합니다.

---

## 설치/실행 – Windows (WSL 권장)

> 가상환경 이름 예시: **whs-windows** (WSL 홈 디렉터리 권장)

1) **WSL 설치(최초 1회, PowerShell 관리자)**
```powershell
wsl --install -d Ubuntu
```

2) **WSL(Ubuntu) 터미널에서 의존 패키지 설치**
```bash
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential   libtsk-dev libewf-dev libbde-dev libfsntfs-dev
```

3) **가상환경 생성/활성화(WSL 홈 경로)**
```bash
mkdir -p ~/venvs
python3 -m venv --prompt whs-windows ~/venvs/whs-windows
source ~/venvs/whs-windows/bin/activate
```

4) **프로젝트 위치로 이동 → 파이썬 의존성 설치**
```bash
cd "/mnt/c/Users/<YOUR_USER>/Desktop/논문/WHS_tool"
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

5) **실행 예시**
```bash
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result
```

성공 시 `./result/CLAUDE/` 하위에 카테고리별로 복사·정리되고, `extracted_paths.txt` 로그가 생성됩니다.

> 팁: venv는 **WSL 홈**에 두고, 소스/데이터(E01)만 `/mnt/c`에서 접근하는 구성이 가장 안정적입니다.

---

## 설치/실행 – macOS

> 가상환경 이름 예시: **whs-macos**

1) **준비**
```bash
xcode-select --install   # 처음이라면 권장
brew update
brew install sleuthkit libewf pkg-config   # 빌드/연동에 도움
```

2) **가상환경 생성/활성화**
```bash
cd /path/to/WHS_tool
python3 -m venv --prompt whs-macos .venv-macos
source .venv-macos/bin/activate
```

3) **파이썬 의존성 설치**
```bash
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

4) **실행 예시**
```bash
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result
```

---

## 사용법(공통 CLI)

```bash
python extract_llm.py <E01_IMAGE_PATH> <MODE> <LLM_NAME> <OUTPUT_DIR>

# 예시
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result
```

- `MODE`: `api` 또는 `standalone`  
- `LLM_NAME`: `CHATGPT`, `CLAUDE`, `LMSTUDIO`, `JAN`  
- `OUTPUT_DIR`: 결과 저장 폴더(없으면 생성)  
- 도구는 이미지 루트 마운트 후, 프로그램별 경로 패턴을 재귀 탐색하여 파일/디렉터리를 복사하고, 추출 경로 로그를 함께 기록합니다.

---

## 결과물

- `./result/<LLM_NAME>/<카테고리>/...` : 추출된 파일/디렉터리  
- `./result/<LLM_NAME>/extracted_paths.txt` : 이미지 내 **발견·추출 경로 목록** 로그

---

### 빠른 실행 요약

**macOS**
```bash
python3 -m venv --prompt whs-macos .venv-macos && source .venv-macos/bin/activate
pip install -r requirements.txt
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result
```

**Windows (WSL)**
```bash
sudo apt update && sudo apt install -y python3-venv python3-dev build-essential   libtsk-dev libewf-dev libbde-dev libfsntfs-dev
python3 -m venv --prompt whs-windows ~/venvs/whs-windows && source ~/venvs/whs-windows/bin/activate
cd "/mnt/c/Users/<YOUR_USER>/Desktop/논문/WHS_tool"
pip install -r requirements.txt
python extract_llm.py ./E01/CLAUDE.E01 api CLAUDE ./result
```
