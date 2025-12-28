import exputil
import time

try:
  from .run_list import *
except (ImportError, SystemError):
  from run_list import *

local_shell = exputil.LocalShell()
max_num_processes = 4

# Check that no screen is running
if local_shell.count_screens() != 0:
    print("There is a screen already running. "
          "Please kill all screens before running this analysis script (killall screen).")
    exit(1)

# Generate the commands

commands_to_run = []

for run in get_tcp_run_list():
    logs_ns3_dir = "runs/" + run["name"] + "/logs_ns3"
    local_shell.remove_force_recursive(logs_ns3_dir)
    local_shell.make_full_dir(logs_ns3_dir)
    
    #print(f"Attacker Gid: {run['from_id']}, VictimGid: {run['to_id']}")
    #commands_to_run.append(
    #   "cd ../../../ns3-sat-sim/simulator; "
    #   "./waf --run=\"main_satnet --run_dir=\\\"../../paper/ns3_experiments/a_b/runs/" + run["name"] +
    #   "\\\" --attackerGid=" + str(run["from_id"]) +
    #   " --victimGid=" + str(run["to_id"]) +
#"\""
#       " 2>&1 | tee '../../paper/ns3_experiments/a_b/" + logs_ns3_dir + "/console.txt'"
#   )
    
   commands_to_run.append(
   "cd ../../../ns3-sat-sim/simulator; " 
   "./waf --run=\"main_satnet --run_dir=\\\"../../paper/ns3_experiments/a_b/runs/" + run["name"] + 
   "\\\" --attackerGid=" + str(run["from_id"]) + 
   " --victimGid=" + str(run["to_id"]) + 
   " --ns3::Log=GSLNetDevice\"" 
   " 2>&1 | tee '../../paper/ns3_experiments/a_b/" + logs_ns3_dir + "/console.txt'" 
)



for run in get_pings_run_list():
   logs_ns3_dir = "runs/" + run["name"] + "/logs_ns3"
   local_shell.remove_force_recursive(logs_ns3_dir)
   local_shell.make_full_dir(logs_ns3_dir)
   commands_to_run.append(
       "cd ../../../ns3-sat-sim/simulator; " 
        "./waf --run=\"main_satnet --run_dir='../../paper/ns3_experiments/a_b/runs/" + run["name"] + "'\" "
        "2>&1 | tee '../../paper/ns3_experiments/a_b/" + logs_ns3_dir + "/console.txt'"
    )

# Run the commands
print("Running commands (at most %d in parallel)..." % max_num_processes)
for i in range(len(commands_to_run)):
    print("Starting command %d out of %d: %s" % (i + 1, len(commands_to_run), commands_to_run[i]))
    local_shell.detached_exec(commands_to_run[i])
    while local_shell.count_screens() >= max_num_processes:
        time.sleep(2)

# Awaiting final completion before exiting
print("Waiting completion of the last %d..." % max_num_processes)
while local_shell.count_screens() > 0:
    time.sleep(2)
print("Finished.")
