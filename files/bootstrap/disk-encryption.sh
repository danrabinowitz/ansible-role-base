#!/bin/bash

# Exit immediately if any command fails.
set -e

# Print a message to stderr when attempting to expand a variable that is not set. Also, immediately exit.
set -u

# Cause pipelines to fail on the first command which fails instead of dying later on down the pipeline.
set -o pipefail

set -x
################################################################################
run_function="${run_function:-main}"

################################################################################


################################################################################
function validate {
  kernel_v=$(uname -r)
  echo "Kernel version: $kernel_v"
}
################################################################################
# TODO: Consider using getopts instead of ENV vars

function main {
  validate # Ensure that arguments and parameters are present and valid
  secure # Ensure that the system is locked down
  access # Ensure that admin access is configured

  >&2 printf "Done!\n"
}
################################################################################
function function_runner {

  >&2 printf "TODO: Abort unless Linux\n"

  case "$run_function" in
    main)
      main
      ;;

    *)
      >&2 printf "FATAL ERROR: Unknown function to run: %s\n" "$run_function"
      exit 1
      ;;
  esac
}
################################################################################
if [[ $UID -ne 0 ]]; then
  sudo -p 'Restarting as root, password: ' run_function="$run_function" bash "$0" "$@"
  exit $?
fi

function_runner
