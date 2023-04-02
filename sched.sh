#!/bin/env bash

readonly SCHEDULER_ENABLED=${SCHEDULER_ENABLED:-1}
readonly SCHEDULER_DEBUG=${SCHEDULER_DEBUG:-0}

readonly SCHEDULER_TASK_HOLDER_ROOT=$(mktemp -d)
readonly SCHEDULER_TASK_HOLDER=$(mktemp ${SCHEDULER_TASK_HOLDER_ROOT}/$$.XXXXXXXXXX)
readonly SCHEDULER_TASK_HOLDER_LOCK=$(mktemp ${SCHEDULER_TASK_HOLDER_ROOT}/$$.XXXXXXXXXX)
readonly SCHEDULER_TASK_FINAL_STATUS=$(mktemp ${SCHEDULER_TASK_HOLDER_ROOT}/$$.XXXXXXXXXX)
readonly SCHEDULER_TASK_LOG_FOLDER=$(mktemp -d)
readonly SCHEDULER_CALLER_VARS=$(set | grep '^[a-zA-Z].*=.*' | sed '$a\ \n')
readonly SCHEDULER_SEPARATOR="@@"
readonly SCHEDULER_TASK_CODE_RUNNABLE="-127"
readonly SCHEDULER_TASK_CODE_RUNNING="-1"
readonly SCHEDULER_TASK_CODE_SUCCEED="0"
readonly SCHEDULER_TASK_INITIAL_PID="PID_PLACEHOLDER"

readonly SCHEDULER_CPU_COUNT=$(cat /proc/stat | grep -c cpu[0-9])
readonly SCHEDULER_DEFAULT_RUNNER_SIZE=$((${SCHEDULER_CPU_COUNT} * 2))
readonly SCHEDULER_MAX_RUNNER_SIZE=${SCHEDULER_MAX_RUNNER_SIZE:-${SCHEDULER_DEFAULT_RUNNER_SIZE}}
readonly SCHEDULER_AVAILABLE_RUNNER_SIZE=$(mktemp ${SCHEDULER_TASK_HOLDER_ROOT}/$$.XXXXXXXXXX)

scheduler_task_id=0

function scheduler::startup() {
  readonly SCHEDULER_TASK_XTRACE_STATE=$(shopt -q -o xtrace; echo $?)
  if ! scheduler::is_enabled; then
    scheduler::log_warn "Scheduler is disabled, switch to serial mode"
    return
  fi
  if [[ ${SCHEDULER_MAX_RUNNER_SIZE} -le 0 ]]; then
    scheduler::log_fatal "SCHEDULER_MAX_RUNNER_SIZE must great than 0"
    exit 1
  fi
  scheduler::log_info "Scheduler startup..."
  scheduler::log_info "SCHEDULER_TASK_HOLDER at $SCHEDULER_TASK_HOLDER"
  echo "${SCHEDULER_MAX_RUNNER_SIZE}" > "${SCHEDULER_AVAILABLE_RUNNER_SIZE}"
  scheduler::dispatcher &
  scheduler_dispatcher_pid=$!
  scheduler::rover &
  scheduler_rover_pid=$!
}

function scheduler::shutdown() {
  scheduler::is_enabled || return 0
  kill -SIGUSR1 ${scheduler_dispatcher_pid} ${scheduler_rover_pid}
  scheduler::terminate_running_tasks
  scheduler::print_pending_tasks
  scheduler::log_info "Scheduler shutdown..."
}

function scheduler::emit() {
  local task_cmd=$1
  if ! scheduler::is_enabled; then
    eval ${task_cmd}
    return
  fi
  scheduler::close_xtrace
  scheduler::init_task "${task_cmd}" "$(scheduler::get_caller_env)"
  scheduler::open_xtrace
}

function scheduler::dispatcher() {
  set +x
  trap 'exit' SIGUSR1
  while true; do
    for task_id in $(scheduler::get_runnable_tasks); do
      [[ "${task_id}" == "" ]] && break
      local task_cmd="$(scheduler::get_task_cmd "${task_id}")"
      scheduler::lease_runner "${task_cmd}" || continue
      local task_logfile="$(scheduler::get_task_logfile "${task_id}")"
      scheduler::set_task_status "${task_id}" "${SCHEDULER_TASK_CODE_RUNNING}"
      scheduler::run_task "${task_id}" &
      local task_pid=$!
      scheduler::set_task_pid "${task_id}" "${task_pid}"
      scheduler::log_info "Task [ ${task_cmd} ] run with PID ${task_pid} Log ${task_logfile}"
    done
    sleep 1
  done
}

function scheduler::rover() {
  set +x
  trap 'exit' SIGUSR1
  while true; do
    while read task; do
      local task_id=${task%%"${SCHEDULER_SEPARATOR}"*}
      local task_cmd="$(scheduler::get_task_cmd "${task_id}")"
      local task_ret=$(scheduler::get_task_status "${task_id}")
      case ${task_ret} in
        ""|${SCHEDULER_TASK_CODE_RUNNABLE}|${SCHEDULER_TASK_CODE_RUNNING}) continue ;;
        ${SCHEDULER_TASK_CODE_SUCCEED})
          scheduler::free_runner "${task_cmd}" || continue
          local task_logfile=$(scheduler::get_task_logfile "${task_id}")
          scheduler::log_info "Task [ ${task_cmd} ] succeeded. Log start ${task_logfile}..."
          tail -n 500 "${task_logfile}"
          echo
          scheduler::remove_task "${task_id}"
          ;;
        *)
          scheduler::free_runner "${task_cmd}" || continue
          local task_logfile=$(scheduler::get_task_logfile "${task_id}")
          scheduler::log_fatal "Task [ ${task_cmd} ] failed. Log start..."
          tail -n 1000 "${task_logfile}"
          scheduler::log_fatal "Please check logs [ ${task_logfile} ] for more info about task [ ${task_cmd} ]. Installer will exit."
          echo "${task_ret}" > ${SCHEDULER_TASK_FINAL_STATUS}
          scheduler::remove_task "${task_id}"
      esac
    done <<<"$(cat "${SCHEDULER_TASK_HOLDER}")"
    sleep 1
  done
}

function scheduler::wait_all_tasks() {
  set +x
  scheduler::is_enabled || return 0
  local need_exit=${1:-0}
  while true; do
    sleep 2
    if [[ -s ${SCHEDULER_TASK_FINAL_STATUS} ]]; then
      exit $(cat "${SCHEDULER_TASK_FINAL_STATUS}")
    elif scheduler::is_tasks_empty; then
      [[ "${need_exit}" == "1" ]] && exit || break
    else
      local task_id=
      for task_id in $(scheduler::get_running_tasks); do
        local task_cmd="$(scheduler::get_task_cmd "${task_id}")"
        local task_logfile="$(scheduler::get_task_logfile "${task_id}")"
        scheduler::log_infonl "Wait for Task [ ${task_cmd} ] Log ${task_logfile}"
        break
      done
    fi
  done
  scheduler::open_xtrace
}

function scheduler::wait_all_tasks_and_exit() { scheduler::wait_all_tasks 1; }

function scheduler::terminate_running_tasks() {
  scheduler::is_tasks_empty && return
  for task_id in $(scheduler::get_running_tasks); do
    local task_pid="$(scheduler::get_task_pid "${task_id}")"
    kill -9 $(ps -eo pid,ppid | awk "\$2==\"${task_pid}\" {print \$1}") "${task_pid}"
    scheduler::log_warn "TASK [ $(scheduler::get_task_cmd "${task_id}") ] terminated"
  done
}

function scheduler::print_pending_tasks() {
  scheduler::is_tasks_empty && return
  local pending_tasks=
  for task_id in $(scheduler::get_runnable_tasks); do
    pending_tasks="[ $(scheduler::get_task_cmd "${task_id}") ], ${pending_tasks}"
  done
  [[ -z "${pending_tasks}" ]] && return
  scheduler::log_warn "Pending tasks: ${pending_tasks}"
}

function scheduler::log_debug() { [[ "${SCHEDULER_DEBUG}" == "1" ]] && echo -e "\033[1;34m[scheduler-debug] $1\033[0m" || true; }

function scheduler::log_info() { echo -e "\033[1;36m[scheduler-info] $1\033[0m"; }

function scheduler::log_infonl() { echo -e -n "\033[37m[scheduler-info] $1\033[0m\r"; }

function scheduler::log_warn() { echo -e "\033[1;33m[scheduler-warn] $1\033[0m"; }

function scheduler::log_fatal() { echo -e "\033[1;31m[scheduler-fatal] $1\033[0m"; }

function scheduler::open_xtrace() { [[ "${SCHEDULER_TASK_XTRACE_STATE}" == "0" ]] && set -x || true; }

function scheduler::close_xtrace() { [[ "${SCHEDULER_TASK_XTRACE_STATE}" == "0" ]] && set +x || true; }

function scheduler::is_enabled() { [[ "${SCHEDULER_ENABLED}" == "1" ]]; }

function scheduler::is_tasks_empty() { [[ ! -s ${SCHEDULER_TASK_HOLDER} ]]; }

function scheduler::lock() { exec 200< "${SCHEDULER_AVAILABLE_RUNNER_SIZE}"; flock -w 1 200; }

function scheduler::unlock() { flock -u 200; }

function scheduler::lease_runner() {
  local task_cmd=$1
  scheduler::lock || return 1
  local available_runner_size=$(cat "${SCHEDULER_AVAILABLE_RUNNER_SIZE}")
  if [[ ${available_runner_size} -gt 0 ]]; then
    echo $((available_runner_size - 1)) > "${SCHEDULER_AVAILABLE_RUNNER_SIZE}"
    scheduler::log_debug "Task [ ${task_cmd} ] lease runner successful. Runner [available $((available_runner_size - 1)), max ${SCHEDULER_MAX_RUNNER_SIZE}]"
    scheduler::unlock
  else
    scheduler::log_debug "Task [ ${task_cmd} ] lease runner failed. Runner [available ${available_runner_size}, max ${SCHEDULER_MAX_RUNNER_SIZE}]"
    scheduler::unlock
    return 1
  fi
}

function scheduler::free_runner() {
  local task_cmd=$1
  scheduler::lock || return 1
  local available_runner_size=$(cat "${SCHEDULER_AVAILABLE_RUNNER_SIZE}")
  if [[ ${available_runner_size} -lt ${SCHEDULER_MAX_RUNNER_SIZE} ]]; then
    echo $((available_runner_size + 1 )) > "${SCHEDULER_AVAILABLE_RUNNER_SIZE}"
    scheduler::log_debug "Task [ ${task_cmd} ] free runner successful. Runner [available $((available_runner_size + 1)), max ${SCHEDULER_MAX_RUNNER_SIZE}]"
    scheduler::unlock
  else
    scheduler::log_debug "Task [ ${task_cmd} ] free runner failed. Runner [available ${available_runner_size}, max ${SCHEDULER_MAX_RUNNER_SIZE}]"
    scheduler::unlock
    return 1
  fi
}

function scheduler::init_task() {
  local task_cmd=$1
  local task_env=$2
  local task_id=$((++scheduler_task_id))
  until flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" grep -q "^${task_id}${SCHEDULER_SEPARATOR}" "${SCHEDULER_TASK_HOLDER}"; do
    flock "${SCHEDULER_TASK_HOLDER_LOCK}" echo "${task_id}${SCHEDULER_SEPARATOR}${task_cmd}${SCHEDULER_SEPARATOR}${SCHEDULER_TASK_CODE_RUNNABLE}${SCHEDULER_SEPARATOR}${SCHEDULER_TASK_INITIAL_PID}${SCHEDULER_SEPARATOR}${SCHEDULER_TASK_LOG_FOLDER}/$RANDOM$RANDOM.log${SCHEDULER_SEPARATOR}${task_env}" >> "${SCHEDULER_TASK_HOLDER}"
  done
}

function scheduler::remove_task() {
  local task_id=$1
  until ! flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" grep -q "^${task_id}${SCHEDULER_SEPARATOR}" "${SCHEDULER_TASK_HOLDER}"; do
    flock "${SCHEDULER_TASK_HOLDER_LOCK}" sed -i "/^"${task_id}${SCHEDULER_SEPARATOR}"/d" ${SCHEDULER_TASK_HOLDER}
  done
}

function scheduler::run_task() {
  local task_id=$1
  trap 'scheduler::set_task_status "${task_id}" $?' EXIT
  eval export $(scheduler::get_task_env "${task_id}") IFS=\" \"
  scheduler::open_xtrace
  eval $(scheduler::get_task_cmd "${task_id}") &> "$(scheduler::get_task_logfile "${task_id}")"
  local ret=$?
  scheduler::close_xtrace
  exit ${ret}
}

function scheduler::get_task_cmd() {
  local task_id=$1
  flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" awk -F "${SCHEDULER_SEPARATOR}" "\$1==\"${task_id}\" {print \$2}" "${SCHEDULER_TASK_HOLDER}"
}

function scheduler::set_task_status() {
  local task_id=$1
  local task_status=$2
  until [[ "$(scheduler::get_task_status "${task_id}")" == "${task_status}" ]]; do
    flock "${SCHEDULER_TASK_HOLDER_LOCK}" sed -i -r "/^"${task_id}${SCHEDULER_SEPARATOR}"/s#${SCHEDULER_SEPARATOR}-?[[:digit:]]+#${SCHEDULER_SEPARATOR}${task_status}#" "${SCHEDULER_TASK_HOLDER}" 2>/dev/null
  done
}

function scheduler::get_task_status() {
  local task_id=$1
  flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" awk -F "${SCHEDULER_SEPARATOR}" "\$1==\"${task_id}\" {print \$3}" "${SCHEDULER_TASK_HOLDER}"
}

function scheduler::set_task_pid() {
  local task_id=$1
  local task_pid=$2
  until [[ "$(scheduler::get_task_pid "${task_id}")" == "${task_pid}" ]]; do
    flock "${SCHEDULER_TASK_HOLDER_LOCK}" sed -i -r "/^"${task_id}${SCHEDULER_SEPARATOR}"/s#${SCHEDULER_SEPARATOR}${SCHEDULER_TASK_INITIAL_PID}#${SCHEDULER_SEPARATOR}${task_pid}#" "${SCHEDULER_TASK_HOLDER}" 2>/dev/null
  done
}

function scheduler::get_task_pid() {
  local task_id=$1
  flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" awk -F "${SCHEDULER_SEPARATOR}" "\$1==\"${task_id}\" {print \$4}" "${SCHEDULER_TASK_HOLDER}"
}

function scheduler::get_task_logfile() {
  local task_id=$1
  flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" awk -F "${SCHEDULER_SEPARATOR}" "\$1==\"${task_id}\" {print \$5}" "${SCHEDULER_TASK_HOLDER}"
}

function scheduler::get_task_env() {
  local task_id=$1
  flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" awk -F "${SCHEDULER_SEPARATOR}" "\$1==\"${task_id}\" {print \$6}" "${SCHEDULER_TASK_HOLDER}"
}

function scheduler::get_caller_env() {
  echo "${SCHEDULER_CALLER_VARS}$(set | grep '^[a-zA-Z].*=.*')" | sort | uniq -u  | grep -v "=$'" | grep -v -E '^(SCHEDULER_|CI_|PIPESTATUS|BASH|SHELL|FUNCNAME).*$' | tr '\n' ' '
}

function scheduler::get_runnable_tasks() {
  flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" awk -F "${SCHEDULER_SEPARATOR}" "\$3==${SCHEDULER_TASK_CODE_RUNNABLE} {print \$1}" "${SCHEDULER_TASK_HOLDER}" | sed ':a;N;$!ba;s/\n/ /g'
}

function scheduler::get_running_tasks() {
  flock -s "${SCHEDULER_TASK_HOLDER_LOCK}" awk -F "${SCHEDULER_SEPARATOR}" "\$3==${SCHEDULER_TASK_CODE_RUNNING} {print \$1}" "${SCHEDULER_TASK_HOLDER}" | sed ':a;N;$!ba;s/\n/ /g'
}

