

shell-sched is a simple concurrent task scheduler based on shell and few GNU tools.

## Features

- Concurrent and asynchronous
- Priority based schedule
- Dynamic tuning and slow start
- Less intrusion

[![quick_start_image](./demo.gif)](https://asciinema.org/a/597018)

## Important

   The scheduler can only be enabled when SCHED_ENABLED=1 (default).

   If not, all task emited run serially as normal rather than exit with error.

## Usage example
   If you want sleep 10 seconds in background:

    # Import all things of sched.sh into current shell proccess.
    source sched.sh 

    # Startup scheduler
    sched::startup

    # Emit a task to scheduler
    sched::emit "sleep 10"

    # Block current proccess for waiting tasks. Optional, if absent, tasks have still be running in background
    sched::wait_all_tasks

    # Shutdown scheduler
    sched::shutdown

## Exposed environment variables
   1. SCHED_ENABLED

        Enable or disable scheduler

        1 -> enable, 0 -> disable

   2. SCHED_DATA_ROOT

       Root path that stored intermediate data on runtime. Default is under /tmp that is generated automaticlly by runtime.

   3. SCHED_MAX_RUNNERS

        Max parrallel task counts. Must be great than 0. Default (2 * cpu cores)
        
   4. SCHED_DEBUG

        Enable or disable scheduler debug log

        1 -> enable, 0 -> disable

# Exposed functions show as below:
   1. sched::startup

        Start scheduler

   2. sched::shutdown

        Stop scheduler

   3. sched::emit \<task\> [\<priority\>]
   
        Emit a task to scheduler which would select a task to execute asynchronously based on its priority

        Note: task must be a function or one-line command

   4. sched::wait_all_tasks_and_exit

        Wait all tasks complete or any error occurred, and exit the calling proceess

   5. sched::wait_all_tasks
   
        Wait all tasks complete or any error occurred, only exit the calling proccess when error occurred
