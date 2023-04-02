

shell-sched is a simple concurrent task scheduler based on shell and few GNU tools.

## Important

   The scheduler can only be enabled when SCHEDULER_ENABLED=1 (default).

   If not, all task emited run serially as normal rather than exit with error.

## Usage example
   If you want sleep 10 seconds in background:

    # Import all things of sched.sh into current shell proccess.
    source sched.sh 

    # Startup scheduler
    scheduler::startup

    # Emit a task to scheduler
    scheduler::emit "sleep 10"

    # Block current proccess for waiting tasks. Optional, if absent, tasks have still be running in background
    scheduler::wait_all_tasks

    # Shutdown scheduler
    scheduler::shutdown

## Exposed environment variables
   1. SCHEDULER_ENABLED

        Enable or disable scheduler

        1 -> enable, 0 -> disable

   2. SCHEDULER_MAX_RUNNER_SIZE

        Max parrallel task counts. Must be great than 0. Default (2 * cpu cores)
        
   3. SCHEDULER_DEBUG

        Enable or disable scheduler debug log

        1 -> enable, 0 -> disable

# Exposed functions show as below:
   1. scheduler::startup

        Start scheduler

   2. scheduler::shutdown

        Stop scheduler

   3. scheduler::emit
   
        Emit a task to scheduler which would select a task to execute asynchronously

   4. scheduler::wait_all_tasks_and_exit

        Wait all tasks complete or any error occurred, and exit the calling proceess

   5. scheduler::wait_all_tasks
   
        Wait all tasks complete or any error occurred, only exit the calling proccess when error occurred
