#!/bin/bash

set -e

MODULE_NAME="abit_probe"
MODULE_FILE="abit_probe.ko"
CHECK_FILE="check_logic.c"
CHECK_BIN="check_logic"

echo "[*] Checking if module is already loaded..."

if lsmod | grep -q "^$MODULE_NAME"; then
    echo "[*] Module already loaded. Skipping insmod."
else
    echo "[*] Module not loaded. Building and inserting..."

    echo "[*] Cleaning build..."
    make clean

    echo "[*] Building module..."
    make

    echo "[*] Inserting module..."
    sudo insmod "$MODULE_FILE"

    echo "[✓] Module inserted successfully"
fi

# ---- Post-check step ----
echo "[*] Sleeping for 1 second..."
sleep 1

echo "[*] Compiling $CHECK_FILE..."
gcc "$CHECK_FILE" -o "$CHECK_BIN"

echo "[*] Running $CHECK_BIN..."
OUTPUT=$("./$CHECK_BIN")

if [ -z "$OUTPUT" ]; then
    echo "[✗] FAILED: No output from check_logic"
    exit 1
else
    echo "[✓] Output from check_logic:"
    echo "$OUTPUT"
fi
