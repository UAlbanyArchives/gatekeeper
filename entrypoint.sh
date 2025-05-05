#!/bin/sh

# Fail on errors
set -e

# Run the Flask app
exec python app/main.py
