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
  rm -rf "$tmp_dir"
}

function configure {
  if [ -z "${SOCAT_SOCKPORT:-}" ]; then
    mode="server"
    PORT="${PORT:-9806}"
    this_script="${BASH_SOURCE[0]}"
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
  echo "Listening on TCP port ${PORT}"
  /usr/local/bin/socat TCP4-LISTEN:"$PORT",reuseaddr,fork SYSTEM:"$this_script"
  echo "socat listener exited"
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

function time_machine {
  # time_machine_*
  >&2 echo "Start of time_machine"

  local enabled
  enabled=$(/usr/bin/defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>/dev/null || true)
  [ "$enabled" = "1" ] || enabled="0"
  add_line "time_machine_enabled ${enabled}"

  if false; then
    >&2 echo "time_machine: Enabled"

    # TODO: Get all destinations, and get a descriptive name for each
    local rc
    i=0
    while true; do
      >&2 echo "time_machine: while loop: i=${i}"

      set +e
      # /usr/libexec/PlistBuddy -c "Print Destinations:$i" /Library/Preferences/com.apple.TimeMachine.plist > /dev/null 2>&1
      # /usr/libexec/PlistBuddy -c "Print Destinations:$i" /Library/Preferences/com.apple.TimeMachine.plist 2>&1
      # /usr/libexec/PlistBuddy -c "Print Destinations:$i" /Library/Preferences/com.apple.TimeMachine.plist > /tmp/log1.djr 2>&1
      /usr/local/sbin/time-machine-plist-reader "Destinations:$i" > /tmp/log1.djr 2>&1
      rc=$?
      set -e
      if [ $rc -ne 0 ]; then
        >&2 echo "time_machine: Error getting destination for i=${i} with rc=${rc}"

        local output
        output=$(/usr/local/sbin/time-machine-plist-reader "Destinations:$i" 2>&1 || true)
        # output=$(/usr/libexec/PlistBuddy -c "Print Destinations:$i" /Library/Preferences/com.apple.TimeMachine.plist 2>&1 || true)

        # TODO: Look for the following message format and return a different exit code:
        # Print: Entry, "Destinations:99", Does Not Exist


        >&2 echo "output from PlistBuddy trying to read destination $i from /Library/Preferences/com.apple.TimeMachine.plist is:"
        >&2 echo "$output"

        >&2 echo "One possible cause could be that this script is lacking Full Disk Access which is required for accessing Time Machine data"
        >&2 echo "  To grant Full Disk Access, open System Preferences > Security & Privacy > Privacy > Full Disk Access, and "
        >&2 id
        >&2 whoami
        break
      fi
      # We have an ith destination
      # Get the alias folder name
      len_hex=$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:BackupAlias" | head -c11 | tail -c1 | xxd -ps)
      len=$((16#$len_hex))
      folder_name=$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:BackupAlias" | head -c$((11+len)) | tail -c"$len")
      >&2 echo "folder_name=$folder_name"


      # Get the last property of the BackupAlias, which is formatted like this:
      # afp://user@host._afpovertcp._tcp.local./Time%20Machine%20Folder
      set +e
      full_name1=$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:BackupAlias" | LANG=C LC_ALL=C sed 's/[^[:print:]\r\t]/ /g' | rev | awk '{print $1}' | rev)
      rc=$?
      set -e
      if [ $rc -ne 0 ]; then
        >&2 echo "Error getting full_name1 for i=$i"
        i=$((i + 1))
        continue
      fi

      length_byte_hex=$(echo -n "$full_name1" | head -c1 | xxd -ps)
      length_byte=$((16#$length_byte_hex))
      length=$((${#full_name1}-1))
      if [ $length_byte -ne $length ]; then
        >&2 echo "Error parsing BackupAlias for i=$i"
        i=$((i + 1))
        continue
      fi

      full_name2=$(echo -n "$full_name1" | tail -c"$length")
      >&2 echo "$full_name2"
      # Parse full_name2 to get host and path
      local host
      host=$(echo "$full_name2" | tr '@.' ' ' | cut -d' ' -f2)

      local head_length
      head_length=$(echo "$full_name2" | sed 's/\/\///' | tr / ' ' | cut -d' ' -f1 | awk '{print length+2}')
      local tail_length
      tail_length=$((${#full_name2}-head_length))
      local path
      path=$(echo -n "$full_name2" | tail -c"$tail_length")
      path=$(urldecode "$path")

      local destination_id
      destination_id=$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:DestinationID")


      local labels
      labels="backup_host=\"${host}\",backup_path=\"${path}\",destination_id=\"${destination_id}\""


      local result
      result=$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:RESULT")
      add_line "time_machine_result{${labels}} ${result}"

      local bytes_used
      bytes_used=$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:BytesUsed")
      add_line "time_machine_bytes_used{${labels}} ${bytes_used}"

      local consistency_scan_at
      consistency_scan_at=$(date -j -f "%a %b %d %T %Z %Y" "$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:ConsistencyScanDate" )" "+%s")
      add_line "time_machine_consistency_scan_at{${labels}} ${consistency_scan_at}"

      local last_known_encryption_state
      last_known_encryption_state=$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:LastKnownEncryptionState")
      if [ "$last_known_encryption_state" = "Encrypted" ]; then
        last_known_encryption_state=1
      else
        last_known_encryption_state=0
      fi
      add_line "time_machine_last_known_encryption_state{${labels}} ${last_known_encryption_state}"

      local bytes_available
      bytes_available=$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:BytesAvailable")
      add_line "time_machine_bytes_available{${labels}} ${bytes_available}"

      local reference_local_snapshot_at
      reference_local_snapshot_at=$(date -j -f "%a %b %d %T %Z %Y" "$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:ReferenceLocalSnapshotDate" )" "+%s")
      add_line "time_machine_reference_local_snapshot_at{${labels}} ${reference_local_snapshot_at}"

      local lastBackupTimestamp
      lastBackupTimestamp=$(date -j -f "%a %b %d %T %Z %Y" "$(/usr/local/sbin/time-machine-plist-reader "Destinations:${i}:SnapshotDates" | tail -n 2 | head -n 1 | awk '{$1=$1};1')" "+%s")
      add_line "time_machine_lastBackupTimestamp{${labels}} ${lastBackupTimestamp}"

      i=$((i + 1))
    done
  fi
}

function ping_metrics {
  # ping_*
  # Set PING_HOSTS in the config file or as an env var, like this.
  # PING_HOSTS=("foo.internal.bar.com" "my-vpn-gateway:192.168.1.1")
  skip=0
  set +u
  [ ${#PING_HOSTS[@]:-0} -eq 0 ] && skip=1
  set -u

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
      # >&2 echo "Waiting for pid=$process_id"
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

      echo "${ping_success}" > /var/lib/node_exporter/textfile_collector/"$host_for_metrics".ping_success

      # >&2 echo "${host_for_metrics}: ping_success=${ping_success} and time_ms=${time_ms} according to i=$i"

      i=$((i + 1))
    done
    rm -rf "${tmp_dir}/ping"
  fi
}

################################################################################
# OS
################################################################################
function darwin {
  # >&2 echo "Start of darwin"
  hid_idle_time
  # >&2 echo "After hid"
  # time_machine
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
  # >&2 echo "Starting generate_http_response_body"

  # Metrics for all/any OS
  ping_metrics

  # >&2 echo "Checking OS"

  if [ "$OS" = "Darwin" ]; then
    darwin
  elif [ "$OS" = "Linux" ]; then
    linux
  else
    echo "Unsupported OS: $OS"
    exit 1
  fi
  # >&2 echo "End of generate_http_response_body"
}

function run_handler {
  trap finish_handler EXIT

  if [ -n "$log_handler" ]; then
    exec 2>/usr/local/var/log/node_exporter_shell_handler.log
  fi
  # >&2 echo "Handler mode"

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

  # >&2 echo "Processing request..."

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
    # >&2 echo "serving metrics"

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
