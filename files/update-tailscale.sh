#!/bin/bash

# Exit immediately if any command fails.
set -e

# Print a message to stderr when attempting to expand a variable that is not set. Also, immediately exit.
set -u

# Cause pipelines to fail on the first command which fails instead of dying later on down the pipeline.
set -o pipefail

set -x
################################################################################
# This script is designed to be run manually, primarily on a MacOS machine.

# TODO: Set up a d2r.io shortcut for this.
# Run something like this:
# sh -c "$(curl -sSL https://d2r.io/macts-update)"


################################################################################
function update_tailscale {
  echo "Updating tailscale..."

  os=$(uname -s | tr '[:upper:]' '[:lower:]')

  if [ "$(uname -m)" = "x86_64" ]; then
    arch="amd64"
  else
    arch="$(uname -m)"
  fi

  osarch="$os-$arch"

  curl -fsSL "https://danrabinowitz01.sfo2.digitaloceanspaces.com/bootstrap/bin/${osarch}/tailscale" > /usr/local/bin/tailscale
  chmod 755 /usr/local/bin/tailscale

  curl -fsSL "https://danrabinowitz01.sfo2.digitaloceanspaces.com/bootstrap/bin/${osarch}/tailscaled" > /tmp/tailscaled
  chmod 755 /tmp/tailscaled

  /tmp/tailscaled install-system-daemon
  # Previous command creates /Library/LaunchDaemons/com.tailscale.tailscaled.plist which could be used to check if it worked.

  # Next command is for install but not update. Maybe the same script should be used, and switch based on presence of auth key.
  echo "No auth key provided -- and functionality to start up is not implemented."
  # tailscale up --authkey="$non_reusable_tailscale_auth_key"

  echo "done"
}

update_tailscale
