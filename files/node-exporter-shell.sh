#!/bin/bash

# Exit immediately if any command fails.
set -e

# Print a message to stderr when attempting to expand a variable that is not set. Also, immediately exit.
set -u

# Cause pipelines to fail on the first command which fails instead of dying later on down the pipeline.
set -o pipefail

################################################################################
# Init
################################################################################
function finish_handler {
  >&2 echo "finish_handler: Cleaning up"
  rm -rf "$tmp_dir"
}

function configure {
  if [ -z "${SOCAT_SOCKPORT:-}" ]; then
    mode="server"
    PORT="${PORT:-9806}"
    this_script="${BASH_SOURCE[0]}"
    socat_exe="${SOCAT:-socat}"
  else
    mode="handler"

    CFG_FILE="${CFG_FILE:-/etc/node-exporter-darwin.sh}"
    if [ -f "$CFG_FILE" ] && [ -r "$CFG_FILE" ]; then
      # shellcheck source=/dev/null
      source "$CFG_FILE"
    fi

    OS=$(uname)
    # Anything other than "" will cause the handler to log
    log_handler=""

    # CACHE_DIR="${CACHE_DIR:-/var/node-exporter-shell/cache}"
    # mkdir -p "$CACHE_DIR"

    PING_TIMEOUT_SECONDS=2

  fi

}

function init {
  # usage
  configure
}

################################################################################
# Server
################################################################################
function run_server {
  >&2 echo "Listening on TCP port ${PORT}"
  "$socat_exe" TCP4-LISTEN:"$PORT",reuseaddr,fork SYSTEM:"$this_script"
  >&2 echo "socat listener exited"
  exit 1
}

################################################################################
# Individual metrics
################################################################################
function hid_idle_time {
  # hid_idle_time
  # It is fast to get. On the order of 0.03 seconds.
  local hid_idle_time
  hid_idle_time=$(ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print $NF/1000000000; exit}') || true
  add_line "hid_idle_time ${hid_idle_time}"
}

function ping_metrics {
  # ping_*
  # Set PING_HOSTS in the config file or as an env var, like this.
  # PING_HOSTS=("foo.internal.bar.com" "my-vpn-gateway:192.168.1.1")
  skip=0

  # >&2 echo "Checking if PING_HOSTS is defined"
  set +e
  declare -p "PING_HOSTS" &>/dev/null
  rc=$?
  set -e

  if [ $rc -ne 0 ]; then
    # >&2 echo "PING_HOSTS is not set. Skipping."
    skip=1
  else
    # >&2 echo "PING_HOSTS is set. If length is 0 then skip."
    [ ${#PING_HOSTS[@]:-0} -eq 0 ] && skip=1
  fi

  # >&2 echo "PING_HOSTS: skip=${skip}"

  if [ $skip -ne 1 ]; then
    mkdir -p "${tmp_dir}/ping"

    declare -a process_ids
    local i
    i=0
    for raw_host in "${PING_HOSTS[@]:-${empty_array[@]}}"; do
      # hostname is what we actually ping
      hostname=$(echo "$raw_host" | cut -d: -f2)
      # >&2 echo "Running ping on $hostname"

      # Run ping in the background
      (ping -n -q -t "$PING_TIMEOUT_SECONDS" -c 1 "$hostname" | grep -E '(rtt|round-trip) ' | sed -E 's/^.+ = ([[:digit:]\.]+)\/.+$/\1/' > "${tmp_dir}/ping/${i}") &
      process_id=$!
      # >&2 echo "pid for $hostname is $process_id"
      process_ids+=("$process_id")

      i=$((i + 1))
    done

    for process_id in "${process_ids[@]}"; do
      # >&2 echo "ping_metrics: Waiting for pid=$process_id"
      wait "$process_id" || true
    done

    # >&2 echo "All pings complete"
    i=0
    for raw_host in "${PING_HOSTS[@]:-${empty_array[@]}}"; do
      # host is the descriptive name that prometheus uses
      host=$(echo "$raw_host" | cut -d: -f1)
      host_for_metrics=$(echo "$host" | sed 's/[\.-]/_/g')
      # time_ms="${ping_times[$i]}"
      time_ms=$(cat "${tmp_dir}/ping/${i}")

      if [ -n "$time_ms" ]; then
        ping_success=1
      else
        ping_success=0
        time_ms=-1
      fi
      add_line "ping_success_${host_for_metrics} ${ping_success}"
      add_line "ping_time_${host_for_metrics}_ms ${time_ms}"

      set +e
      echo "${ping_success}" > /var/lib/node_exporter/textfile_collector/"$host_for_metrics".ping_success
      set -e

      # >&2 echo "${host_for_metrics}: ping_success=${ping_success} and time_ms=${time_ms} according to i=$i"

      i=$((i + 1))
    done
    rm -rf "${tmp_dir}/ping"
  fi
}

function custom_metrics_scripts {
  # For each file
  # NODE_EXPORTER_SHELL_METRICS_SCRIPT_DIRS=/usr/local/bin/node-exporter-shell/metrics-scripts
  if [ -n "${NODE_EXPORTER_SHELL_METRICS_SCRIPT_DIRS:-}" ]; then
    local local_tmp_dir
    local_tmp_dir="${tmp_dir}/custom_metrics"
    mkdir -p "$local_tmp_dir"

    declare -a process_ids
    local i
    i=0

    for dir in $NODE_EXPORTER_SHELL_METRICS_SCRIPT_DIRS; do
      >&2 echo "Processing custom metrics scripts in $dir"
      for file in "$dir"/*; do
        >&2 echo "Processing file $file"
        if [[ -x "$file" ]]; then
          ("$file" > "${local_tmp_dir}/${i}") &
          # process_ids+=($!)
          process_id=$!
          process_ids+=("$process_id")
          i=$((i + 1))
        fi
      done
    done

    if [ $i -gt 0 ]; then
      for process_id in "${process_ids[@]}"; do
        >&2 echo "custom_metrics_scripts: Waiting for pid=$process_id"
        wait "$process_id" || true
      done
    fi

    # >&2 echo "All ${i} custom metrics scripts are complete"
    local max
    max=$i
    local out1
    for ((i=0;i<max;i++)); do
        # >&2 echo "Reading from output file for i=${i}"
        if [ -r "${local_tmp_dir}/${i}" ]; then
          out1=$(<"${local_tmp_dir}/${i}")
          # TODO: Be sure this handles multiple lines
          add_line "$out1"
        else
          >&2 echo "Unable to read file for i=${i}"
        fi
    done

    rm -rf "$local_tmp_dir"
  fi
}

################################################################################
# OS
################################################################################
function darwin {
  # >&2 echo "Start of darwin"
  hid_idle_time
  # >&2 echo "After hid"
  # >&2 echo "End of darwin"
}

function linux {
    echo "Unsupported OS: $OS"
    exit 1
}

################################################################################
# Handler
################################################################################
function add_line {
  local line
  line="$1"
  local lf
  lf=$'\n'
  # if [ -z "$http_response_body" ]; then
  http_response_body="${http_response_body}${line}${lf}"
  # else
  # fi

  # >&2 echo "add_line: $line"

}

function generate_http_response_body {
  >&2 echo "Starting generate_http_response_body"

  # Metrics for all/any OS
  ping_metrics

  >&2 echo "Checking OS"

  if [ "$OS" = "Darwin" ]; then
    darwin
  # elif [ "$OS" = "Linux" ]; then
  #   linux
  # else
  #   echo "Unsupported OS: $OS"
  #   exit 1
  fi

  custom_metrics_scripts

  >&2 echo "End of generate_http_response_body"
}

function run_handler {
  trap finish_handler EXIT

  if [ -n "$log_handler" ]; then
    exec 2>/usr/local/var/log/node_exporter_shell_handler.log
  fi
  >&2 echo "Handler mode"

  tmp_dir=$(mktemp -d -t node-exporter-bash-XXXXXXXX)

  CR=$(echo -en '\r')

  http_request_method=""
  http_header_lines=()
  headers_complete=0
  while read -t 1 -r line; do
    # >&2 echo "line=$line"
    # echo -ne "$line" | hexdump
    if [ -z "$http_request_method" ]; then
      # >&2 echo "Reading first line..."
      http_request_method=$(echo "$line" | awk '{print $1}')
      # >&2 echo "http_request_method=${http_request_method}"
      http_request_url=$(echo "$line" | awk '{print $2}')
      # >&2 echo "http_request_url=${http_request_url}"
      http_request_version=$(echo "$line" | awk '{print $3}')
      # >&2 echo "http_request_version=${http_request_version}"
    elif [ "$line" = "$CR" ]; then
      # >&2 echo "blank line: End of headers"
      headers_complete=1
    elif [ "$headers_complete" -ne 1 ]; then
      # >&2 echo "This is a header line. Adding to array."
      http_header_lines+=("$line")
    else
      >&2 echo "http request body"
    fi
  done

  # >&2 echo "headers_complete=${headers_complete}"
  if [ "$headers_complete" -ne 1 ]; then
    >&2 echo "ERROR: Failed to finish reading headers"
    echo -e "HTTP/1.1 400 Bad Request\r"
    echo -e "\r"
    exit 0
  fi

  >&2 echo "Processing request..."

  # pattern='^(([[:alnum:]]+)://)?(([[:alnum:]]+)@)?([^:^@]+)(:([[:digit:]]+))?$'
  # pattern='(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
  # pattern='(?i)\b((?:[a-z][\w-]+:(?:/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'"'"'".,<>?«»“”‘’]))'

  # if [[ "$http_request_url" =~ $pattern ]]; then
  #   proto=${BASH_REMATCH[2]}
  #   user=${BASH_REMATCH[4]}
  #   host=${BASH_REMATCH[5]}
  #   port=${BASH_REMATCH[7]}

  #   echo "proto=$proto"
  #   echo "user=$user"
  #   echo "host=$host"
  #   echo "port=$port"
  # fi

  # >&2 echo "Parsing http_request_url=${http_request_url}"
  set +e
  # extract the protocol
  proto="$(echo "$http_request_url" | grep :// | sed -e's,^\(.*://\).*,\1,g')"
  # echo "proto=$proto"
  # remove the protocol
  url="$(echo ${http_request_url/$proto/})"
  # echo "url=$url"
  # extract the user (if any)
  user="$(echo "$url" | grep @ | cut -d@ -f1)"
  # extract the host and port
  hostport="$(echo "${url/$user@/}" | cut -d/ -f1)"
  # by request host without port
  host="$(echo $hostport | sed -e 's,:.*,,g')"
  # by request - try to extract the port
  port="$(echo "$hostport" | sed -e 's,^.*:,:,g' -e 's,.*:\([0-9]*\).*,\1,g' -e 's,[^0-9],,g')"
  # extract the path (if any)
  path="/$(echo "$url" | grep / | cut -d/ -f2-)"
  set -e

  >&2 echo "HTTP Request received: url=${http_request_url} parsed into host=${host}, port=${port}, and path=${path}"

  if [ "$http_request_method" = "GET" ] && [ "$path" = "/metrics" ]; then
    >&2 echo "serving metrics"

    http_response_body=""
    generate_http_response_body

    echo -e "HTTP/1.1 200 OK\r"
    echo -e "\r"
    echo -n "$http_response_body"
  else
    >&2 echo "404 Not Found"
    echo -e "HTTP/1.1 404 Not Found\r"
    echo -e "\r"
    exit 0
  fi

}
################################################################################
# Helpers
################################################################################
function urldecode() { : "${*//+/ }"; echo -e "${_//%/\\x}"; }

################################################################################
# Main
################################################################################
function main {
  init

  if [ "$mode" = "server" ]; then
    run_server
  fi
  run_handler
}
main
