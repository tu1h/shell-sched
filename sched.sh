function sched::startup() {
  readonly SCHED_ENABLED=${SCHED_ENABLED:-1}
  if ! sched::is_enabled; then
    sched::log_warn "Scheduler is disabled, switch to serial mode"
    return
  fi

  readonly SCHED_DATA_ROOT=${SCHED_DATA_ROOT:-$(mktemp -d)}
  readonly SCHED_TASK_HOLDER=$(mktemp -p ${SCHED_DATA_ROOT} $$.XXXXXXXXXX)
  readonly SCHED_TASK_HOLDER_LOCK=$(mktemp -p ${SCHED_DATA_ROOT} $$.XXXXXXXXXX)
  readonly SCHED_TASK_FINAL_STATUS=$(mktemp -p ${SCHED_DATA_ROOT} $$.XXXXXXXXXX)
  readonly SCHED_TASK_LOG_FOLDER=$(mktemp -p ${SCHED_DATA_ROOT} -d)
  readonly SCHED_CALLER_VARS=$(set | grep '^[a-zA-Z].*=.*' | sed '$a\ \n')
  readonly SCHED_SEPARATOR="@@"
  readonly SCHED_TASK_CODE_RUNNABLE="-127"
  readonly SCHED_TASK_CODE_RUNNING="-1"
  readonly SCHED_TASK_CODE_SUCCEED="0"
  readonly SCHED_TASK_INITIAL_PID="PID_PLACEHOLDER"

  readonly SCHED_CPU_COUNT=$(cat /proc/stat | grep -c cpu[0-9])
  readonly SCHED_DEFAULT_RUNNERS=$((${SCHED_CPU_COUNT} * 2))
  readonly SCHED_MAX_RUNNERS=${SCHED_MAX_RUNNERS:-${SCHED_DEFAULT_RUNNERS}}
  readonly SCHED_ACTIVE_RUNNERS=$(mktemp -p ${SCHED_DATA_ROOT} $$.XXXXXXXXXX)
  readonly SCHED_AVAILABLE_RUNNERS=$(mktemp -p ${SCHED_DATA_ROOT} $$.XXXXXXXXXX)
  if [[ ${SCHED_MAX_RUNNERS} -le 0 ]]; then
    sched::log_fatal "SCHED_MAX_RUNNERS must great than 0"
    exit 1
  fi

  readonly SCHED_DEBUG=${SCHED_DEBUG:-0}
  readonly SCHED_ALLOW_FAILED=${SCHED_ALLOW_FAILED:-0}
  readonly SCHED_TASK_XTRACE_STATE=$(shopt -q -o xtrace; echo $?)

  sched::log_info "Sched startup..."
  sched::log_info "tasks holder at $SCHED_TASK_HOLDER"
  sched_task_id=0
  echo "${SCHED_MAX_RUNNERS}" > "${SCHED_ACTIVE_RUNNERS}"
  echo "${SCHED_MAX_RUNNERS}" > "${SCHED_AVAILABLE_RUNNERS}"
  sched::dispatcher &
  sched_dispatcher_pid=$!
  sched::rover &
  sched_rover_pid=$!
  sched::runner_tuner &
  sched_tuner_pid=$!
}

function sched::shutdown() {
  sched::is_enabled || return 0
  kill -SIGUSR1 ${sched_dispatcher_pid} ${sched_rover_pid} ${sched_tuner_pid} || true
  sched::terminate_running_tasks
  sched::print_pending_tasks
  sched::log_info "Sched shutdown..."
}

function sched::emit() {
  set +x
  local task_cmd=$1
  local task_priority=${2:-0}
  if ! sched::is_enabled; then
    eval "sched::open_xtrace && ${task_cmd}"
  else
    if [[ ! ${task_priority} =~ ^-?[0-9]+$ ]]; then
      sched::log_fatal "Task priority must be a number"
      exit 1
    fi
    sched::init_task "${task_cmd}" "$(sched::get_caller_env)" "${task_priority}"
    sched::open_xtrace
  fi
}

function sched::dispatcher() { 
  set +x
  trap 'exit' SIGUSR1
  while true; do
    sleep 0.1
    local task_id=$(sched::pick_task)
    [[ -z "${task_id}" ]] && continue
    local task_cmd="$(sched::get_task_cmd "${task_id}")"
    sched::lease_runner "${task_cmd}" || continue
    local task_logfile="$(sched::get_task_logfile "${task_id}")"
    sched::set_task_status "${task_id}" "${SCHED_TASK_CODE_RUNNING}"
    sched::run_task "${task_id}" &
    local task_pid=$!
    sched::set_task_pid "${task_id}" "${task_pid}"
    sched::log_info "Task ${task_id} [ ${task_cmd} ] run with PID ${task_pid} Log ${task_logfile}"
  done
}

function sched::rover() {
  set +x
  trap 'exit' SIGUSR1
  while true; do
    while read task; do
      local task_id=${task%%"${SCHED_SEPARATOR}"*}
      local task_cmd="$(sched::get_task_cmd "${task_id}")"
      local task_ret=$(sched::get_task_status "${task_id}")
      case ${task_ret} in
        ""|${SCHED_TASK_CODE_RUNNABLE}|${SCHED_TASK_CODE_RUNNING}) continue ;;
        ${SCHED_TASK_CODE_SUCCEED})
          sched::free_runner "${task_cmd}" || continue
          local task_logfile=$(sched::get_task_logfile "${task_id}")
          sched::log_info "Task ${task_id} succeeded. Log start..."
          cat "${task_logfile}"
          echo
          sched::remove_task "${task_id}"
          ;;
        *)
          sched::free_runner "${task_cmd}" || continue
          local task_logfile=$(sched::get_task_logfile "${task_id}")
          sched::log_fatal "Task ${task_id} [ ${task_cmd} ] failed. Log start..."
          cat "${task_logfile}"
          echo "${task_ret}" > ${SCHED_TASK_FINAL_STATUS}
          sched::remove_task "${task_id}"
      esac
    done <<<"$(cat "${SCHED_TASK_HOLDER}")"
    sleep 1
  done
}

function sched::wait_all_tasks() {
  set +x
  sched::is_enabled || return 0
  local need_exit=${1:-0}
  local last_seek=
  while true; do
    sleep 0.5
    if [[ "${SCHED_ALLOW_FAILED}" == 0  && -s ${SCHED_TASK_FINAL_STATUS} ]]; then
      exit $(cat "${SCHED_TASK_FINAL_STATUS}")
    elif sched::is_tasks_empty; then
      [[ "${need_exit}" == "1" ]] && exit || break
    else
      local tasks=($(sched::get_running_tasks))
      [ "${#tasks[@]}" == 0 ] && continue
      local task_id=${tasks[$((RANDOM % ${#tasks[@]}))]}
      [[ "${task_id}" == "${last_seek}" ]] && continue
      sched::log_infonl "Wait for Task ${task_id} Log $(sched::get_task_logfile "${task_id}")"
      last_seek=${task_id}
    fi
  done
  sched::open_xtrace
}

function sched::wait_all_tasks_and_exit() { sched::wait_all_tasks 1; }

function sched::terminate_running_tasks() {
  sched::is_tasks_empty && return
  for task_id in $(sched::get_running_tasks); do
    local task_pid="$(sched::get_task_pid "${task_id}")"
    kill $(ps -eo pid,ppid | awk "\$2==\"${task_pid}\" {print \$1}") "${task_pid}"
    sched::log_warn "TASK ${task_id} [ $(sched::get_task_cmd "${task_id}") ] terminated"
  done
}

function sched::print_pending_tasks() {
  sched::is_tasks_empty && return
  local pending_tasks=
  for task_id in $(sched::get_runnable_tasks); do
    pending_tasks="[ $(sched::get_task_cmd "${task_id}") ], ${pending_tasks}"
  done
  [[ -z "${pending_tasks}" ]] && return
  sched::log_warn "Pending tasks: ${pending_tasks}"
}

function sched::log_debug() { [[ "${SCHED_DEBUG}" == "1" ]] && echo -e "\033[K\033[34m[sched-debug] $1\033[0m" || true; }

function sched::log_info() { echo -e "\033[K\033[36m[sched-info] $1\033[0m"; }

function sched::log_infonl() { echo -e -n "\033[K\033[37m[sched-info] $1\033[0m\r"; }

function sched::log_warn() { echo -e "\033[K\033[33m[sched-warn] $1\033[0m"; }

function sched::log_fatal() { echo -e "\033[K\033[31m[sched-fatal] $1\033[0m"; }

function sched::open_xtrace() { [[ "${SCHED_TASK_XTRACE_STATE}" == "0" ]] && set -x || true; }

function sched::close_xtrace() { [[ "${SCHED_TASK_XTRACE_STATE}" == "0" ]] && set +x || true; }

function sched::is_enabled() { [[ "${SCHED_ENABLED}" == "1" ]]; }

function sched::is_tasks_empty() { [[ ! -s ${SCHED_TASK_HOLDER} ]]; }

function sched::lock() { exec 200< "${SCHED_AVAILABLE_RUNNERS}"; flock -w 1 200; }

function sched::unlock() { flock -u 200; }

function sched::lease_runner() {
  local task_cmd=$1
  sched::lock || return 1
  local available_runner_size=$(cat "${SCHED_AVAILABLE_RUNNERS}")
  local active_runner_size=$(cat "${SCHED_ACTIVE_RUNNERS}")
  local leased_runners=$((SCHED_MAX_RUNNERS - available_runner_size))
  if [[ ${available_runner_size} -gt 0 ]] && [[ ${active_runner_size} -gt ${leased_runners} ]]; then
    echo $((available_runner_size - 1)) > "${SCHED_AVAILABLE_RUNNERS}"
    sched::log_debug "Task [ ${task_cmd} ] lease runner successful. Runner [available $((available_runner_size - 1)), active ${active_runner_size}, max ${SCHED_MAX_RUNNERS}]"
    sched::unlock
  else
    sched::log_debug "Task [ ${task_cmd} ] lease runner failed. Runner [available ${available_runner_size}, active ${active_runner_size}, max ${SCHED_MAX_RUNNERS}]"
    sched::unlock
    return 1
  fi
}

function sched::free_runner() {
  local task_cmd=$1
  sched::lock || return 1
  local available_runner_size=$(cat "${SCHED_AVAILABLE_RUNNERS}")
  local active_runner_size=$(cat "${SCHED_ACTIVE_RUNNERS}")
  if [[ ${available_runner_size} -lt ${SCHED_MAX_RUNNERS} ]]; then
    echo $((available_runner_size + 1 )) > "${SCHED_AVAILABLE_RUNNERS}"
    sched::log_debug "Task [ ${task_cmd} ] free runner successful. Runner [available $((available_runner_size + 1)), active ${active_runner_size}, max ${SCHED_MAX_RUNNERS}]"
    sched::unlock
  else
    sched::log_debug "Task [ ${task_cmd} ] free runner failed. Runner [available ${available_runner_size}, active ${active_runner_size}, max ${SCHED_MAX_RUNNERS}]"
    sched::unlock
    return 1
  fi
}

function sched::runner_tuner() {
  set +x
  trap 'exit' SIGUSR1
  # proportional gain control
  local gain=0.8
  local target_load=1.5

  local num_runner_raw=1
  local num_runners=${NUM_RUNNERS_RAW}

  while true; do
    local load_factor=$(awk -v x=$(cut -d " " -f 1 /proc/loadavg) -v y=${SCHED_CPU_COUNT} 'BEGIN{printf "%.2f", x/y}')
    local adjust=$(awk -v x=${target_load} -v y=${load_factor} -v z=${gain} 'BEGIN{printf "%.2f", (x-y)*z}')

    local new_runners_raw=$(awk -v x=${num_runner_raw} -v y=${adjust} 'BEGIN{printf "%.2f", x + y}')
    local new_runners=$(printf "%.f" ${new_runners_raw})

    if [[ ${new_runners} -lt 1 ]]; then
      num_runners=1
    elif [[ ${new_runners} -gt ${SCHED_MAX_RUNNERS} ]]; then
      num_runners=${SCHED_MAX_RUNNERS}
    else
      num_runners=${new_runners}
      num_runner_raw=${new_runners_raw}
    fi  

    sched::lock || continue
    local active_runners=$(cat "${SCHED_ACTIVE_RUNNERS}")
    if [[ ${active_runners} -ne ${num_runners} ]]; then
      echo ${num_runners} > "${SCHED_ACTIVE_RUNNERS}"
      sched::log_debug "Runner tuned [previous ${active_runners}, current ${num_runners}]"
    fi
    sched::unlock
    sleep 3
  done
}

function sched::init_task() {
  local task_cmd=$1
  local task_env=$2
  local task_priority=$3
  local task_id=$((++sched_task_id))
  until flock -s "${SCHED_TASK_HOLDER_LOCK}" grep -q "^${task_id}${SCHED_SEPARATOR}" "${SCHED_TASK_HOLDER}"; do
    flock "${SCHED_TASK_HOLDER_LOCK}" echo "${task_id}${SCHED_SEPARATOR}${task_cmd}${SCHED_SEPARATOR}${SCHED_TASK_CODE_RUNNABLE}${SCHED_SEPARATOR}${SCHED_TASK_INITIAL_PID}${SCHED_SEPARATOR}${SCHED_TASK_LOG_FOLDER}/$RANDOM$RANDOM.log${SCHED_SEPARATOR}${task_env}${SCHED_SEPARATOR}${task_priority}" >> "${SCHED_TASK_HOLDER}"
  done
}

function sched::remove_task() {
  local task_id=$1
  until ! flock -s "${SCHED_TASK_HOLDER_LOCK}" grep -q "^${task_id}${SCHED_SEPARATOR}" "${SCHED_TASK_HOLDER}"; do
    flock "${SCHED_TASK_HOLDER_LOCK}" sed -i "/^"${task_id}${SCHED_SEPARATOR}"/d" ${SCHED_TASK_HOLDER}
  done
}

function sched::run_task() {
  local task_id=$1
  local task_cmd=$(sched::get_task_cmd "${task_id}")
  local task_logfile=$(sched::get_task_logfile "${task_id}")
  trap '(sched::set_task_status "${task_id}" $?) 2>/dev/null' EXIT
  eval export $(sched::get_task_env "${task_id}") IFS=\"$' \t\n'\"
  eval "sched::open_xtrace && ${task_cmd}" &> "${task_logfile}"
  exit $?
}

function sched::get_task_cmd() {
  local task_id=$1
  flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$1==\"${task_id}\" {print \$2}" "${SCHED_TASK_HOLDER}"
}

function sched::set_task_status() {
  local task_id=$1
  local task_status=$2
  until [[ "$(sched::get_task_status "${task_id}")" == "${task_status}" ]]; do
    flock "${SCHED_TASK_HOLDER_LOCK}" sed -i -r "/^"${task_id}${SCHED_SEPARATOR}"/s#${SCHED_SEPARATOR}-?[[:digit:]]+#${SCHED_SEPARATOR}${task_status}#" "${SCHED_TASK_HOLDER}" 2>/dev/null
  done
}

function sched::get_task_status() {
  local task_id=$1
  flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$1==\"${task_id}\" {print \$3}" "${SCHED_TASK_HOLDER}"
}

function sched::set_task_pid() {
  local task_id=$1
  local task_pid=$2
  until [[ "$(sched::get_task_pid "${task_id}")" == "${task_pid}" ]]; do
    flock "${SCHED_TASK_HOLDER_LOCK}" sed -i -r "/^"${task_id}${SCHED_SEPARATOR}"/s#${SCHED_SEPARATOR}${SCHED_TASK_INITIAL_PID}#${SCHED_SEPARATOR}${task_pid}#" "${SCHED_TASK_HOLDER}" 2>/dev/null
  done
}

function sched::get_task_pid() {
  local task_id=$1
  flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$1==\"${task_id}\" {print \$4}" "${SCHED_TASK_HOLDER}"
}

function sched::get_task_logfile() {
  local task_id=$1
  flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$1==\"${task_id}\" {print \$5}" "${SCHED_TASK_HOLDER}"
}

function sched::get_task_env() {
  local task_id=$1
  flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$1==\"${task_id}\" {print \$6}" "${SCHED_TASK_HOLDER}"
}

function sched::get_caller_env() {
  local sched_caller_env=
  local env_tmp=$(echo "${SCHED_CALLER_VARS}$(set | grep '^[a-zA-Z].*=.*')" | sort | uniq -u  | grep -v "=$'" | grep -v -E '^(sched_|SCHED_|CI_|PIPESTATUS|BASH|SHELL|FUNCNAME).*$')
  while IFS=$'\n' read -r env; do
    local same_env=false
    for var in ${SCHED_CALLER_VARS}; do
      [ "$env" == "$var" ] && same_env=true && break
    done
    $same_env || sched_caller_env+=" $env "
  done <<<"$env_tmp"
  echo "$sched_caller_env"
}

function sched::pick_task() {
  sched::get_priority_runnable_tasks 1 | awk '{print $1}'
}

function sched::get_priority_runnable_tasks() {
  local select_priority=${1:-0}
  if [ ${select_priority} == 0 ]; then
    flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$3==${SCHED_TASK_CODE_RUNNABLE} {print \$1,\$7}" "${SCHED_TASK_HOLDER}" | sort -rnk2 | awk '{print $1}' | sed ':a;N;$!ba;s/\n/ /g'
  else
    flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$3==${SCHED_TASK_CODE_RUNNABLE} {print \$1,\$7}" "${SCHED_TASK_HOLDER}" | sort -rnk2 | awk 'NR==1 || arr[1]==$2 {arr[NR]=$2; print $1 | "sort -n"}' | sed ':a;N;$!ba;s/\n/ /g'
  fi
}

function sched::get_runnable_tasks() {
  flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$3==${SCHED_TASK_CODE_RUNNABLE} {print \$1}" "${SCHED_TASK_HOLDER}" | sed ':a;N;$!ba;s/\n/ /g'
}

function sched::get_running_tasks() {
  flock -s "${SCHED_TASK_HOLDER_LOCK}" awk -F "${SCHED_SEPARATOR}" "\$3==${SCHED_TASK_CODE_RUNNING} {print \$1}" "${SCHED_TASK_HOLDER}" | sed ':a;N;$!ba;s/\n/ /g'
}
