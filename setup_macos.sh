#!/bin/bash

# --- Script Execution Options ---
# -e: Exit immediately if a command exits with a non-zero status.
# -o pipefail: The return value of a pipeline is the status of the last command to exit with a non-zero status.
set -eo pipefail

# --- Configuration Variables ---
# Define the path for the virtual environment (e.g., .venv-macos in the project folder).
VENV_NAME=".venv-macos"
VENV_PATH="./$VENV_NAME"

# --- Color Codes ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Helper Function ---
# Checks for the existence of a command, e.g., Homebrew.
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# --- Script Start ---
echo -e "${GREEN}Starting the WHS_tool macOS environment setup script.${NC}"

# 1. Check for requirements.txt to verify the script is run from the project root.
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}Error: 'requirements.txt' not found.${NC}"
    echo "This script must be run from the root directory of the WHS_tool project."
    exit 1
fi

# 2. Check for Homebrew installation and update.
echo -e "\n${GREEN}[1/4] Checking for Homebrew and updating...${NC}"
if ! command_exists brew; then
    echo -e "${RED}Error: Homebrew is not installed.${NC}"
    echo "Please install Homebrew first. Website: https://brew.sh/"
    exit 1
else
    echo "Homebrew found. Proceeding with update..."
    brew update
fi

# 3. Install native libraries using Homebrew.
# sleuthkit, libewf, and pkg-config are required to resolve forensic library dependencies.
echo -e "\n${GREEN}[2/4] Installing native libraries (sleuthkit, libewf, pkg-config)...${NC}"
brew install sleuthkit libewf pkg-config

# 4. Create Python virtual environment.
echo -e "\n${GREEN}[3/4] Creating Python virtual environment...${NC}"
if [ -d "$VENV_PATH" ]; then
    echo -e "${YELLOW}Virtual environment already exists at '$VENV_PATH'. Skipping creation.${NC}"
else
    # Explicitly run with the python3 command.
    python3 -m venv --prompt "whs-macos" "$VENV_PATH"
    echo "Successfully created virtual environment at '$VENV_PATH'."
fi

# 5. Install Python packages into the virtual environment.
echo -e "\n${GREEN}[4/4] Installing Python packages into the virtual environment...${NC}"
# Use pip from the created virtual environment to install packages from requirements.txt.
"$VENV_PATH/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_PATH/bin/pip" install -r requirements.txt

# --- Completion Message ---
echo -e "\n${GREEN}=======================================================${NC}"
echo -e "${GREEN} Setup complete!${NC}"
echo -e "To activate the virtual environment, run the following command:"
echo -e "${YELLOW}source $VENV_PATH/bin/activate${NC}"
echo -e "${GREEN}=======================================================${NC}"
