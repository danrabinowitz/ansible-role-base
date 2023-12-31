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
function build_shufflecake_kernel_module {
  sudo apt install "linux-headers-$(uname -r)" libdevmapper-dev libgcrypt-dev
  libgcrypt-config --version
  cd ~
  git clone https://codeberg.org/shufflecake/shufflecake-c.git
  cd shufflecake-c

  sudo apt install make gcc

  # The next line is from here: https://askubuntu.com/a/1404795
  sudo ln -sf "/usr/lib/modules/$(uname -r)/vmlinux.xz" /boot/

  make

  sudo mkdir -p "/lib/modules/$(uname -r)/kernel/drivers/shufflecake"
  sudo cp dm-sflc.ko "/lib/modules/$(uname -r)/kernel/drivers/shufflecake"

  sudo sh -c 'echo "shufflecake/dm-sflc" >> /etc/modules'

  # Then, back on the host:
  # scp linux-sandbox:shufflecake-c/shufflecake ~/code/src/danrabinowitz/ServerManagement/docker-workdir/ansible/roles/danrabinowitz-role-base/files/bootstrap/shufflecake/6.5.0-14
  # scp linux-sandbox:shufflecake-c/dm-sflc.ko ~/code/src/danrabinowitz/ServerManagement/docker-workdir/ansible/roles/danrabinowitz-role-base/files/bootstrap/shufflecake/6.5.0-14
}

function install_shufflecake {
  scp ~/code/src/danrabinowitz/ServerManagement/docker-workdir/ansible/roles/danrabinowitz-role-base/files/bootstrap/shufflecake/6.5.0-14/* linux-sandbox:
}

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
