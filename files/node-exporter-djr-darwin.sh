#!/bin/bash

# Exit immediately if any command fails.
set -e

# Print a message to stderr when attempting to expand a variable that is not set. Also, immediately exit.
set -u

# Cause pipelines to fail on the first command which fails instead of dying later on down the pipeline.
set -o pipefail

################################################################################
function configure {
  if [ -z "${SOCAT_SOCKPORT:-}" ]; then
    mode="server"
    PORT="${PORT:-9806}"
    this_script="${BASH_SOURCE[0]}"
  else
    mode="handler"

    CFG_FILE="${CFG_FILE:-/etc/node-exporter-darwin.sh}"
    # shellcheck source=/dev/null
    source "$CFG_FILE"
  fi
}

function init {
  # usage
  configure
}

function run_server {
  echo "Listening on TCP port ${PORT}"
  /usr/local/bin/socat TCP4-LISTEN:"$PORT",reuseaddr,fork SYSTEM:"$this_script"
  echo "socat listener exited"
  exit 1
}

function add_line {
  local line
  line="$1"
  local lf
  lf=$'\n'
  # if [ -z "$http_response_body" ]; then
  http_response_body="${http_response_body}${line}${lf}"
  # else
  # fi
}

function generate_http_response_body {
  # hid_idle_time
  # It is fast to get. On the order of 0.03 seconds.
  hid_idle_time=$(ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print $NF/1000000000; exit}') || true
  add_line "hid_idle_time ${hid_idle_time}"
  # http_response_body="${line}${lf}"

  # ping_*
  # It is quite slow. We should look into parallelizing this.
  # Set PING_HOSTS in the config file or as an env var, like this.
  # PING_HOSTS=("foo.internal.bar.com" "my-vpn-gateway:192.168.1.1")
  skip=0
  set +u
  [ ${#PING_HOSTS[@]:-0} -eq 0 ] && skip=1
  set -u

  if [ $skip -ne 1 ]; then
    for raw_host in "${PING_HOSTS[@]:-${empty_array[@]}}"; do
      # host is the descriptive name that prometheus uses
      host=$(echo "$raw_host" | cut -d: -f1)
      # hostname is what we actually ping
      hostname=$(echo "$raw_host" | cut -d: -f2)

      host_for_metrics=$(echo "$host" | sed 's/[\.-]/_/g')

      set +e
      time_ms=$(ping -n -q -c 1 "$hostname" | grep -E '(rtt|round-trip) ' | sed -E 's/^.+ = ([[:digit:]\.]+)\/.+$/\1/')
      set -e

      if [ -n "$time_ms" ]; then
        ping_success=1
      else
        ping_success=0
        time_ms=-1
      fi
      add_line "ping_success_${host_for_metrics} ${ping_success}"
      # http_response_body="${line}${lf}"

      add_line "ping_time_${host_for_metrics}_ms ${time_ms}"
    done
  fi

  # time_machine_*
  enabled=$(/usr/bin/defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup)
# if [ "$enabled" == "1" ];then
# lastBackupTimestamp=`date -j -f "%a %b %d %T %Z %Y" "$(/usr/libexec/PlistBuddy -c "Print Destinations:0:SnapshotDates" /Library/Preferences/com.apple.TimeMachine.plist | tail -n 2 | head -n 1 | awk '{$1=$1};1')" "+%Y-%m-%d %H:%M:%S"`
# echo "<result>$lastBackupTimestamp</result>"
# else
# echo "<result>Disabled</result>"
# fi


}

function run_handler {
  # >&2 echo "Handler mode"
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

function main {
  init

  if [ "$mode" = "server" ]; then
    run_server
  fi
  run_handler
}
main
