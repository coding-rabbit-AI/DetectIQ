#!/bin/sh

# Set environment variables.
APP_NAME="DetectIQ"
ENV_FILE="./.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "[x] '${ENV_FILE}' not found"
    exit 1
fi
. "$ENV_FILE"

# Install the project.
install() {
    make install/local APP_NAME="$APP_NAME"
}

# Run the project.
run() {
    make run/local APP_NAME="$APP_NAME"
}

# Print script options.
help() {
    echo -e "\033[1;31m[!] Please choose a valid option:\033[0m"
    echo "- install"
    echo "- run"
}

# Parse the user's choice.
case $1 in
    install)
        install
        ;;
    run)
        run
        ;;
    *)
        help
        ;;
esac
