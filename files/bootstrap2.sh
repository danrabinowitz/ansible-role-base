#!/bin/bash

# Exit immediately if any command fails.
set -e

# Print a message to stderr when attempting to expand a variable that is not set. Also, immediately exit.
set -u

# Cause pipelines to fail on the first command which fails instead of dying later on down the pipeline.
set -o pipefail

# set -x
################################################################################
# This script is designed to be run in two cases:
# 1) from cloud-init, from a per-once script
# 2) manually, when setting up a new machine that doesn't use cloud-init
################################################################################
function validate {
  >&2 printf "Validating...\n"
}

function secure {
  >&2 printf "Securing...\n"
}

function access {
  >&2 printf "Ensuring access...\n"
}
################################################################################
function main {
  printf "Start: STDOUT\n"
  >&2 printf "Start: STDERR\n"
  printf "Start: Console\n" > /dev/ttyAMA0

  validate # Ensure that arguments and parameters are present and valid
  secure # Ensure that the system is locked down
  access # Ensure that admin access is configured
}
################################################################################
main
