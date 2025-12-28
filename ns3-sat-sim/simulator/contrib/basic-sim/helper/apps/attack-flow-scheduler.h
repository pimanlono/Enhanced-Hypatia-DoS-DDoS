/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 ETH Zurich
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Simon
 * Originally based on, but since heavily adapted/extended, the scratch/main authored by Hussain.
 */
#ifndef ATTACK_FLOW_SCHEDULER_H
#define ATTACK_FLOW_SCHEDULER_H

#include <map>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <chrono>
#include <stdexcept>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/random-variable-stream.h"
#include "ns3/command-line.h"

#include "ns3/basic-simulation.h"
#include "ns3/exp-util.h"
#include "ns3/topology.h"

#include "ns3/tcp-flow-schedule-reader.h"
#include "ns3/tcp-flow-send-helper.h"
#include "ns3/tcp-flow-send-application.h"
#include "ns3/tcp-flow-sink-helper.h"
#include "ns3/tcp-flow-sink.h"

#include "ns3/attack-flow-schedule-reader.h"

//NEW : 
// New includes for SYN flood attack
#include "ns3/syn-attack-helper.h"
#include "ns3/syn-attack-application.h"

#include "ns3/icmp-attack-helper.h"
#include "ns3/icmp-attack-application.h"

#include "ns3/udp-attack-helper.h"
#include "ns3/udp-attack-application.h"

namespace ns3 {

class AttackFlowScheduler: public Object //new
{

public:
    static TypeId GetTypeId (void); //new
    
    AttackFlowScheduler (); //new
    AttackFlowScheduler(Ptr<BasicSimulation> basicSimulation, Ptr<Topology> topology);
    void WriteResults();

protected:
    void StartNextFlow(int i);
    Ptr<BasicSimulation> m_basicSimulation;
    int64_t m_simulation_end_time_ns;
    Ptr<Topology> m_topology = nullptr;
    bool m_enabled;

    std::vector<AttackFlowScheduleEntry> m_schedule;
    NodeContainer m_nodes;
    std::vector<ApplicationContainer> m_apps;
    std::set<int64_t> m_enable_logging_for_syn_flow_ids; //NEW
    std::set<int64_t> m_enable_logging_for_icmp_flow_ids;
    std::set<int64_t> m_enable_logging_for_udp_flow_ids;
    uint32_t m_system_id;
    bool m_enable_distributed;
    std::vector<int64_t> m_distributed_node_system_id_assignment;
    //New members for SYN, ICMP, UDP flows
    std::string m_syn_flows_csv_filename;
    std::string m_syn_flows_txt_filename;
    std::string m_icmp_flows_csv_filename;
    std::string m_icmp_flows_txt_filename;
    std::string m_udp_flows_csv_filename;
    std::string m_udp_flows_txt_filename;
};

}

#endif /* ATTACK_FLOW_SCHEDULER_H */
