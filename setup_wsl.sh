#!/bin/bash

# --- 스크립트 실행 옵션 ---
# -e: 명령어가 실패하면 즉시 스크립트를 종료한다.
# -o pipefail: 파이프라인에서 중간 명령어가 실패해도 전체를 실패로 간주한다.
set -eo pipefail

# --- 설정 변수 ---
# 가상환경을 생성할 경로를 지정한다.
VENV_DIR="$HOME/venvs"
VENV_NAME="whs-windows"
VENV_PATH="$VENV_DIR/$VENV_NAME"

# --- 색상 코드 ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- 스크립트 시작 ---
echo -e "${GREEN}Starting the WHS_tool WSL environment setup script.${NC}"

# 1. requirements.txt 파일 확인
if [ ! -f "requirements.txt" ]; then
    echo -e "${YELLOW}Error: 'requirements.txt' not found.${NC}"
    echo "This script must be run from the root directory of the WHS_tool project."
    exit 1
fi

# 2. 네이티브 라이브러리 설치
echo -e "\n${GREEN}[1/3] Installing native libraries... (sudo password may be required)${NC}"
sudo apt-get update
sudo apt-get install -y python3-venv python3-dev build-essential libtsk-dev libewf-dev libbde-dev libfsntfs-dev

# 3. Python 가상환경 생성
echo -e "\n${GREEN}[2/3] Creating Python virtual environment...${NC}"
if [ -d "$VENV_PATH" ]; then
    echo -e "${YELLOW}Virtual environment already exists at '$VENV_PATH'. Skipping creation.${NC}"
else
    mkdir -p "$VENV_DIR"
    python3 -m venv --prompt "$VENV_NAME" "$VENV_PATH"
    echo "Virtual environment successfully created at '$VENV_PATH'."
fi

# 4. Python 패키지 설치
echo -e "\n${GREEN}[3/3] Installing Python packages into the virtual environment...${NC}"
# 생성된 가상환경의 pip를 사용하여 requirements.txt 파일의 패키지를 설치한다.
"$VENV_PATH/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_PATH/bin/pip" install -r requirements.txt

# --- 완료 메시지 ---
echo -e "\n${GREEN}=======================================================${NC}"
echo -e "${GREEN} Setup complete!${NC}"
echo -e "To activate the virtual environment, run the following command:"
echo -e "${YELLOW}source $VENV_PATH/bin/activate${NC}"
echo -e "${GREEN}=======================================================${NC}"