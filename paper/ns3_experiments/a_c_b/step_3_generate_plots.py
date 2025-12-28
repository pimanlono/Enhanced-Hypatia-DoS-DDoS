import exputil
import csv
import re
from run_list import get_tcp_run_list

local_shell = exputil.LocalShell()

# Remove and create directories
local_shell.remove_force_recursive("pdf")
local_shell.make_full_dir("pdf")
local_shell.remove_force_recursive("data")
local_shell.make_full_dir("data")

def get_flow_ids(schedule_file):    
    legitimate_flows = []
    malicious_flows = []
    
    with open(schedule_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row:
                if len(row) >= 7 and (row[6] == "synflood" or row[6]=="icmpflood" or row[6]=="udpflood"):
                    malicious_flows.append(row[0])
#                elif row[0] == "0":  # Solo agregar el flujo 0 que tiene logging habilitado
#                    legitimate_flows.append(row[0])
                else:
                     legitimate_flows.append(row[0])

    return legitimate_flows, malicious_flows

# TCP runs
for run in get_tcp_run_list():
   local_shell.make_full_dir("pdf/" + run["name"])
   local_shell.make_full_dir("data/" + run["name"])
   
   # Extract flow IDs from schedule.csv
   schedule_file = "runs/" + run["name"] + "/schedule.csv"
   print(f"Checking file: {schedule_file}")
   
   legitimate_flows, malicious_flows = get_flow_ids(schedule_file)
   
   # Print info about malicious flows
   for flow_id in malicious_flows:
       print(f"Ploteo de flujo malicioso {flow_id} aún no implementado.")
   
   # Process legitimate flows
   for flow_id in legitimate_flows:
       local_shell.perfect_exec(
           "cd ../../../ns3-sat-sim/simulator/contrib/basic-sim/tools/plotting/plot_tcp_flow; "
           "python3 plot_tcp_flow.py "
           "../../../../../../../paper/ns3_experiments/a_c_b/runs/" + run["name"] + "/logs_ns3 "
           "../../../../../../../paper/ns3_experiments/a_c_b/data/" + run["name"] + " "
           "../../../../../../../paper/ns3_experiments/a_c_b/pdf/" + run["name"] + " "
           f"{flow_id} " + str(1 * 1000 * 1000 * 1000),
           output_redirect=exputil.OutputRedirect.CONSOLE
       )
