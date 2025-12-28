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

#include "attack-flow-scheduler.h"
#include "ns3/log.h"//NEW


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("AttackFlowScheduler");

NS_OBJECT_ENSURE_REGISTERED (AttackFlowScheduler);


TypeId
AttackFlowScheduler::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::AttackFlowScheduler")
    .SetParent<Object> ()
    .SetGroupName ("Applications")
    .AddConstructor<AttackFlowScheduler> ();
  return tid;
}
AttackFlowScheduler::AttackFlowScheduler() :
    m_basicSimulation(0),
    m_topology(0),
    m_enabled(false),
    m_system_id(0),
    m_enable_distributed(false)
{
    NS_LOG_FUNCTION(this);
} 


void AttackFlowScheduler::StartNextFlow(int i) {

    // Fetch the flow to start
    AttackFlowScheduleEntry& entry = m_schedule[i];
    int64_t now_ns = Simulator::Now().GetNanoSeconds();
    NS_ASSERT(now_ns == entry.GetStartTimeNs());

     //NEW :FLOWS DIFFERENTIATION
    // Get metadata to determine flow type
    std::string metadata = entry.GetMetadata();

    ApplicationContainer app;
    
    if (metadata == "shrew"){

	// Sintaxis in schedule file: FlowId - FromNodeId - ToNodeId - Attack Duration - Start time - Shrew Attack Params (a string separed by &)- shrew

        NS_LOG_INFO("Installing UDP Shrew attack flow " << entry.GetAttackFlowId() 
                    << " from node " << entry.GetFromNodeId() 
                    << " to node " << entry.GetToNodeId() 
                    << "\nFlow will start at t= " << entry.GetStartTimeNs()/1e9 << " s "
		    << "attack duration " << entry.GetSizeByte()/1e9 << " s "
		    << "attack parameters " << entry.GetAdditionalParameters());

	std::stringstream ss(entry.GetAdditionalParameters());
	std::string token;
	std::vector<std::string> parts;

    	int64_t burst_period = 0;
    	int64_t burst_length = 0;
    	int64_t attacker_rate = 0;

	Ptr<UniformRandomVariable> randPort = CreateObject<UniformRandomVariable>();
	uint16_t randomPort = randPort->GetInteger(1025, 65535);

	while (std::getline(ss,token,'&')){parts.push_back(token);}

	if (parts.size() == 3) {
        burst_period  = std::stoll(parts[0]);
        burst_length  = std::stoll(parts[1]);
        attacker_rate = std::stoll(parts[2]);
	
	NS_LOG_INFO("burst_period: "<<burst_period
			<<" burst_length: "<<burst_length
			<<" attacker_rate: "<<attacker_rate);
	} else {
        NS_LOG_INFO("Error: attack parameters: burst_period&burst_length&attacker_rate");
    	}


        //IP VERIFICATIONS 
        // Obtain and verify malicious source address
        Ptr<Ipv4> ipv4_src = m_nodes.Get(entry.GetFromNodeId())->GetObject<Ipv4>();
        Ipv4Address srcAddr = ipv4_src->GetAddress(1,0).GetLocal();
        NS_LOG_INFO("Source address (C): " << srcAddr);

        // Obtain and verify target address
        Ptr<Ipv4> ipv4_dst = m_nodes.Get(entry.GetToNodeId())->GetObject<Ipv4>();
        Ipv4Address dstAddr = ipv4_dst->GetAddress(1,0).GetLocal();
        NS_LOG_INFO("Target address (B): " << dstAddr);

        // Verify that both addresses are valid
        NS_ASSERT_MSG(srcAddr != Ipv4Address("0.0.0.0"), "Invalid source address for node " << entry.GetFromNodeId());
        NS_ASSERT_MSG(dstAddr != Ipv4Address("0.0.0.0"), "Invalid target address for node " << entry.GetToNodeId());

        int64_t stopTimeNs = entry.GetStartTimeNs() + entry.GetSizeByte();  // SizeByte field is used for attack duration

	//Create malicious UDP Shrew application
	//It is a UDP On-Off Application. It is not required to code an ad-hoc application
	OnOffHelper onoff("ns3::UdpSocketFactory", Address(InetSocketAddress(dstAddr, randomPort)));  //UDP_SINK_PORT:9001
	onoff.SetConstantRate(DataRate(attacker_rate));;
	std::ostringstream onTimeStr,offTimeStr;
	onTimeStr << "ns3::ConstantRandomVariable[Constant=" <<burst_length/1e9<<"]";
	offTimeStr << "ns3::ConstantRandomVariable[Constant=" <<burst_period/1e9-burst_length/1e9<<"]";
	onoff.SetAttribute("OnTime", StringValue(onTimeStr.str()));
	onoff.SetAttribute("OffTime",StringValue(offTimeStr.str()));
	ApplicationContainer onoffApp=onoff.Install(m_nodes.Get(entry.GetFromNodeId()));
	//onoffApp.Start(NanoSeconds(entry.GetStartTimeNs()));
	onoffApp.Start(NanoSeconds(0));
	//onoffApp.Stop(NanoSeconds(stopTimeNs));
	onoffApp.Stop(NanoSeconds(entry.GetSizeByte()));

	//UDP sink on the receiver
	PacketSinkHelper UDPsink("ns3::UdpSocketFactory", Address(InetSocketAddress(dstAddr, randomPort)));
        ApplicationContainer UDPSinkApp = UDPsink.Install(m_nodes.Get(entry.GetToNodeId()));
        UDPSinkApp.Start(Seconds(0.0));
        UDPSinkApp.Stop(NanoSeconds(stopTimeNs));


    }

    else if (metadata == "synflood") {
	// Sintaxis in schedule file: FlowId - FromNodeId - ToNodeId - Time between packets - Start time - Attack Duration - synflood
	// AttackDuration is declared as text, so it is converted to uint64_t using std::stoull()
	
        NS_LOG_INFO("Installing SYN flood attack flow " << entry.GetAttackFlowId() 
                    << " from node " << entry.GetFromNodeId() 
                    << " to node " << entry.GetToNodeId() 
                    << "\nFlow will start at t= " << entry.GetStartTimeNs()/1e9 << " s "
		    << "send a TCP-SYN every "<< entry.GetSizeByte()/1e9 << "s"
		    << "attack duration " << std::stoull(entry.GetAdditionalParameters())/1e9 << " s ");

        //IP VERIFICATIONS 
        // Obtain and verify malicious source address
        Ptr<Ipv4> ipv4_src = m_nodes.Get(entry.GetFromNodeId())->GetObject<Ipv4>();
        Ipv4Address srcAddr = ipv4_src->GetAddress(1,0).GetLocal();
        NS_LOG_INFO("Source address (C): " << srcAddr);

        // Obtain and verify target address
        Ptr<Ipv4> ipv4_dst = m_nodes.Get(entry.GetToNodeId())->GetObject<Ipv4>();
        Ipv4Address dstAddr = ipv4_dst->GetAddress(1,0).GetLocal();
        NS_LOG_INFO("Target address (B): " << dstAddr);

        // Verify that both addresses are valid
        NS_ASSERT_MSG(srcAddr != Ipv4Address("0.0.0.0"), "Invalid source address for node " << entry.GetFromNodeId());
        NS_ASSERT_MSG(dstAddr != Ipv4Address("0.0.0.0"), "Invalid target address for node " << entry.GetToNodeId());

        int64_t stopTimeNs = entry.GetStartTimeNs() + std::stoull(entry.GetAdditionalParameters()); 

	// Create malicious SYN flood application
        SynAttackHelper attacker(
            "ns3::Ipv4RawSocketFactory",
            InetSocketAddress(m_nodes.Get(entry.GetToNodeId())->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(), 1024),
            entry.GetAttackFlowId(),
            true,
            m_basicSimulation->GetLogsDir(),
            entry.GetSizeByte(), //  TCP-SYN sending interval in ns
	    std::stoull(entry.GetAdditionalParameters()) //Attack duration
        );
        NS_LOG_INFO("TCP-SYN Attack Flow will stop at t=" << stopTimeNs/1e9 << "s");
        // Install it on the node and start it right now
        app = attacker.Install(m_nodes.Get(entry.GetFromNodeId()));
        app.Start(NanoSeconds(0));
	//app.Stop(NanoSeconds(stopTimeNs));
	app.Stop(NanoSeconds(std::stoull(entry.GetAdditionalParameters())));
	m_apps.push_back(app);
    }
    else if (metadata == "udpflood") {
	// Sintaxis in schedule file: FlowId - FromNodeId - ToNodeId - Time between packets - Start time - Attack Duration - udpflood
	// AttackDuration is declared as text, so it is converted to uint64_t using std::stoull()
	
        NS_LOG_INFO("Installing UDP flood attack flow " << entry.GetAttackFlowId() 
                    << " from node " << entry.GetFromNodeId() 
                    << " to node " << entry.GetToNodeId() 
                    << "\nFlow will start at t= " << entry.GetStartTimeNs()/1e9 << " s "
		    << "send an UDP every "<< entry.GetSizeByte()/1e9 << "s"
		    << "attack duration " << std::stoull(entry.GetAdditionalParameters())/1e9 << " s ");
        
        //IP VERIFICATIONS 
        // Obtain and verify malicious source address
        Ptr<Ipv4> ipv4_src = m_nodes.Get(entry.GetFromNodeId())->GetObject<Ipv4>();
        Ipv4Address srcAddr = ipv4_src->GetAddress(1,0).GetLocal();
        NS_LOG_INFO("Source address (C): " << srcAddr);

        // Obtain and verify target address
        Ptr<Ipv4> ipv4_dst = m_nodes.Get(entry.GetToNodeId())->GetObject<Ipv4>();
        Ipv4Address dstAddr = ipv4_dst->GetAddress(1,0).GetLocal();
        NS_LOG_INFO("Target address (B): " << dstAddr);

        // Verify that both addresses are valid
        NS_ASSERT_MSG(srcAddr != Ipv4Address("0.0.0.0"), "Invalid source address for node " << entry.GetFromNodeId());
        NS_ASSERT_MSG(dstAddr != Ipv4Address("0.0.0.0"), "Invalid target address for node " << entry.GetToNodeId());

        int64_t stopTimeNs = entry.GetStartTimeNs() + std::stoull(entry.GetAdditionalParameters()); //10-12
        //stopTimeNs=10000000000;	
        // Create malicious UDP flood application
        UdpAttackHelper attacker(
            "ns3::UdpSocketFactory",
            InetSocketAddress(m_nodes.Get(entry.GetToNodeId())->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(), 1024),
            entry.GetAttackFlowId(),
            true,
            m_basicSimulation->GetLogsDir(),
            entry.GetSizeByte(), // UDP sending interval in ns 
	    std::stoull(entry.GetAdditionalParameters()) //Attack duration
        );
        NS_LOG_INFO("UDP Attack Flow will stop at t=" << stopTimeNs/1e9 << "s");
        // Install it on the node and start it right now
        app = attacker.Install(m_nodes.Get(entry.GetFromNodeId()));
        app.Start(NanoSeconds(0));
	//app.Stop(NanoSeconds(stopTimeNs));
	app.Stop(NanoSeconds(std::stoull(entry.GetAdditionalParameters())));
	m_apps.push_back(app);
    }

    else if (metadata == "icmpflood") {
	// Sintaxis in schedule file: FlowId - FromNodeId - ToNodeId - Time between packets - Start time - Attack Duration - icmpflood
	// AttackDuration is declared as text, so it is converted to uint64_t using std::stoull()
	
        NS_LOG_INFO("Installing ICMP flood attack flow " << entry.GetAttackFlowId() 
                    << " from node " << entry.GetFromNodeId() 
                    << " to node " << entry.GetToNodeId() 
                    << "\nFlow will start at t= " << entry.GetStartTimeNs()/1e9 << " s "
		    << "send an ICMP every "<< entry.GetSizeByte()/1e9 << "s"
		    << "attack duration " << std::stoull(entry.GetAdditionalParameters())/1e9 << " s ");
        
        //IP VERIFICATIONS 
        // Obtain and verify malicious source address
        Ptr<Ipv4> ipv4_src = m_nodes.Get(entry.GetFromNodeId())->GetObject<Ipv4>();
        Ipv4Address srcAddr = ipv4_src->GetAddress(1,0).GetLocal();
        NS_LOG_INFO("Source address (C): " << srcAddr);

        // Obtain and verify target address
        Ptr<Ipv4> ipv4_dst = m_nodes.Get(entry.GetToNodeId())->GetObject<Ipv4>();
        Ipv4Address dstAddr = ipv4_dst->GetAddress(1,0).GetLocal();
        NS_LOG_INFO("Target address (B): " << dstAddr);

        // Verify that both addresses are valid
        NS_ASSERT_MSG(srcAddr != Ipv4Address("0.0.0.0"), "Invalid source address for node " << entry.GetFromNodeId());
        NS_ASSERT_MSG(dstAddr != Ipv4Address("0.0.0.0"), "Invalid target address for node " << entry.GetToNodeId());

        
        int64_t stopTimeNs = entry.GetStartTimeNs() + std::stoull(entry.GetAdditionalParameters()); //10-12
        //stopTimeNs=10000000000;	
        // Create malicious SYN flood application
        IcmpAttackHelper attacker(
            "ns3::Ipv4RawSocketFactory",
            InetSocketAddress(m_nodes.Get(entry.GetToNodeId())->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(), 1024),
            entry.GetAttackFlowId(),
            true,
            m_basicSimulation->GetLogsDir(),
            entry.GetSizeByte(), //  ICMP sending interval in ns
	    std::stoull(entry.GetAdditionalParameters()) //Attack duration
        );
        NS_LOG_INFO("ICMP Attack Flow will stop at t=" << stopTimeNs/1e9 << "s");
        // Install it on the node and start it right now
        app = attacker.Install(m_nodes.Get(entry.GetFromNodeId()));
        app.Start(NanoSeconds(0));
	//app.Stop(NanoSeconds(stopTimeNs));
	app.Stop(NanoSeconds(std::stoull(entry.GetAdditionalParameters())));
	m_apps.push_back(app);
    }
    else {
	    std::cout<<"nada"<<std::endl;
    }

    //PILAR - lo he movido a cada caso
    //app.Start(NanoSeconds(0));
    //m_apps.push_back(app);

    // If there is a next flow to start, schedule its start
    if (i + 1 != (int) m_schedule.size()) {
        int64_t next_flow_ns = m_schedule[i + 1].GetStartTimeNs();
        Simulator::Schedule(NanoSeconds(next_flow_ns - now_ns), &AttackFlowScheduler::StartNextFlow, this, i + 1);
    }
}

AttackFlowScheduler::AttackFlowScheduler(Ptr<BasicSimulation> basicSimulation, Ptr<Topology> topology) {
    printf("ATTACK FLOW SCHEDULER\n");

    m_basicSimulation = basicSimulation;
    m_topology = topology;

    // Check if it is enabled explicitly
    m_enabled = parse_boolean(m_basicSimulation->GetConfigParamOrDefault("enable_attack_flow_scheduler", "false"));
    if (!m_enabled) {
        std::cout << "  > Not enabled explicitly, so disabled" << std::endl;

    } else {
        std::cout << "  > Attack flow scheduler is enabled" << std::endl;

        // Properties we will use often
        m_nodes = m_topology->GetNodes();
        m_simulation_end_time_ns = m_basicSimulation->GetSimulationEndTimeNs();
        m_system_id = m_basicSimulation->GetSystemId();
	m_enable_distributed = m_basicSimulation->IsDistributedEnabled();
        m_distributed_node_system_id_assignment = m_basicSimulation->GetDistributedNodeSystemIdAssignment();
	
	//NEW
	m_enable_logging_for_syn_flow_ids = parse_set_positive_int64(
                m_basicSimulation->GetConfigParamOrDefault("syn_flow_enable_logging_for_syn_flow_ids", "set()"));

	m_enable_logging_for_icmp_flow_ids = parse_set_positive_int64(
                m_basicSimulation->GetConfigParamOrDefault("icmp_flow_enable_logging_for_icmp_flow_ids", "set()"));

	m_enable_logging_for_udp_flow_ids = parse_set_positive_int64(
                m_basicSimulation->GetConfigParamOrDefault("udp_flow_enable_logging_for_udp_flow_ids", "set()"));

	// Read schedule
        std::vector<AttackFlowScheduleEntry> complete_schedule = read_attack_flow_schedule(
                m_basicSimulation->GetRunDir() + "/" + m_basicSimulation->GetConfigParamOrFail("attack_flow_schedule_filename"),
                m_topology,
                m_simulation_end_time_ns
        );

        // Check that the flow IDs exist in the logging

        for (int64_t attack_flow_id : m_enable_logging_for_syn_flow_ids) {
            if ((size_t) attack_flow_id >= complete_schedule.size()) {
                throw std::invalid_argument("Invalid SYN flow ID in syn_flow_enable_logging_for_attack_flow_ids: " + std::to_string(attack_flow_id));
            }
	}

        for (int64_t attack_flow_id : m_enable_logging_for_icmp_flow_ids) {
            if ((size_t) attack_flow_id >= complete_schedule.size()) {
                throw std::invalid_argument("Invalid ICMP flow ID in icmp_flow_enable_logging_for_attack_flow_ids: " + std::to_string(attack_flow_id));
            }
        }

        for (int64_t attack_flow_id : m_enable_logging_for_udp_flow_ids) {
            if ((size_t) attack_flow_id >= complete_schedule.size()) {
                throw std::invalid_argument("Invalid UDP flow ID in udp_flow_enable_logging_for_attack_flow_ids: " + std::to_string(attack_flow_id));
            }
        }


        // Filter the schedule to only have applications starting at nodes which are part of this system
        if (m_enable_distributed) {
            std::vector<AttackFlowScheduleEntry> filtered_schedule;
            for (AttackFlowScheduleEntry &entry : complete_schedule) {
                if (m_distributed_node_system_id_assignment[entry.GetFromNodeId()] == m_system_id) {
                    filtered_schedule.push_back(entry);
                }
            }
            m_schedule = filtered_schedule;
        } else {
            m_schedule = complete_schedule;
        }

        // Schedule read
        printf("  > Read schedule (total flow start events: %lu)\n", m_schedule.size());
        m_basicSimulation->RegisterTimestamp("Read flow schedule");

        // Determine filenames
        if (m_enable_distributed) {
            m_syn_flows_csv_filename =
                    m_basicSimulation->GetLogsDir() + "/system_" + std::to_string(m_system_id) + "_syn_flows.csv";
            m_syn_flows_txt_filename =
                    m_basicSimulation->GetLogsDir() + "/system_" + std::to_string(m_system_id) + "_syn_flows.txt";

            m_icmp_flows_csv_filename =
                    m_basicSimulation->GetLogsDir() + "/system_" + std::to_string(m_system_id) + "_icmp_flows.csv";
            m_icmp_flows_txt_filename =
                    m_basicSimulation->GetLogsDir() + "/system_" + std::to_string(m_system_id) + "_icmp_flows.txt";

            m_udp_flows_csv_filename =
                    m_basicSimulation->GetLogsDir() + "/system_" + std::to_string(m_system_id) + "_udp_flows.csv";
            m_udp_flows_txt_filename =
                    m_basicSimulation->GetLogsDir() + "/system_" + std::to_string(m_system_id) + "_udp_flows.txt";
        } else {
            m_syn_flows_csv_filename = m_basicSimulation->GetLogsDir() + "/syn_flows.csv";
            m_syn_flows_txt_filename = m_basicSimulation->GetLogsDir() + "/syn_flows.txt";

            m_icmp_flows_csv_filename = m_basicSimulation->GetLogsDir() + "/icmp_flows.csv";
            m_icmp_flows_txt_filename = m_basicSimulation->GetLogsDir() + "/icmp_flows.txt"; 

            m_udp_flows_csv_filename = m_basicSimulation->GetLogsDir() + "/udp_flows.csv";
            m_udp_flows_txt_filename = m_basicSimulation->GetLogsDir() + "/udp_flows.txt"; 

	}

        // Remove files if they are there
	remove_file_if_exists(m_syn_flows_csv_filename);//NEW
        remove_file_if_exists(m_syn_flows_txt_filename);//NEW
	remove_file_if_exists(m_icmp_flows_csv_filename);//NEW
        remove_file_if_exists(m_icmp_flows_txt_filename);//NEW
	remove_file_if_exists(m_udp_flows_csv_filename);//NEW
        remove_file_if_exists(m_udp_flows_txt_filename);//NEW
        printf("  > Removed previous flow log files if present\n");
        m_basicSimulation->RegisterTimestamp("Remove previous flow log files");

	/*
        // Install sink on each endpoint node
        std::cout << "  > Setting up TCP flow sinks" << std::endl;
        for (int64_t endpoint : m_topology->GetEndpoints()) {
            if (!m_enable_distributed || m_distributed_node_system_id_assignment[endpoint] == m_system_id) {
                TcpFlowSinkHelper sink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), 1024));

		//19-11 NEW: Añadir configuración de logging
        	
        	sink.SetAttribute("BaseLogsDir", StringValue(m_basicSimulation->GetLogsDir()));
		//--------------------------------
                ApplicationContainer app = sink.Install(m_nodes.Get(endpoint));
                app.Start(Seconds(0.0));
            }
        }
        m_basicSimulation->RegisterTimestamp("Setup TCP flow sinks");
	*/

        // Setup start of first source application
        std::cout << "  > Setting up traffic Attack flow starter" << std::endl;
        if (m_schedule.size() > 0) {
            Simulator::Schedule(NanoSeconds(m_schedule[0].GetStartTimeNs()), &AttackFlowScheduler::StartNextFlow, this, 0);
        }
        m_basicSimulation->RegisterTimestamp("Setup traffic Attack flow starter");
	
    }

    std::cout << std::endl;
}

void AttackFlowScheduler::WriteResults() {
    std::cout << "STORE ATTACK FLOW RESULTS" << std::endl;

    // Check if it is enabled explicitly
    if (!m_enabled) {
        std::cout << "  > Not enabled, so no flow results are written" << std::endl;
        return;
    }

    //NEW Files for malicious flows
    std::cout << "  > Opening SYN flow log files:" << std::endl;
    FILE* syn_csv = fopen(m_syn_flows_csv_filename.c_str(), "w+");
    std::cout << "    >> Opened: " << m_syn_flows_csv_filename << std::endl;
    FILE* syn_txt = fopen(m_syn_flows_txt_filename.c_str(), "w+");
    std::cout << "    >> Opened: " << m_syn_flows_txt_filename << std::endl;

    std::cout << "  > Opening ICMP flow log files:" << std::endl;
    FILE* icmp_csv = fopen(m_icmp_flows_csv_filename.c_str(), "w+");
    std::cout << "    >> Opened: " << m_icmp_flows_csv_filename << std::endl;
    FILE* icmp_txt = fopen(m_icmp_flows_txt_filename.c_str(), "w+");
    std::cout << "    >> Opened: " << m_icmp_flows_txt_filename << std::endl;

    std::cout << "  > Opening UDP flow log files:" << std::endl;
    FILE* udp_csv = fopen(m_udp_flows_csv_filename.c_str(), "w+");
    std::cout << "    >> Opened: " << m_udp_flows_csv_filename << std::endl;
    FILE* udp_txt = fopen(m_udp_flows_txt_filename.c_str(), "w+");
    std::cout << "    >> Opened: " << m_udp_flows_txt_filename << std::endl;

    // Headers
    std::cout << "  > Writing flow headers" << std::endl;
    
    // NEW SYN flows header
    fprintf(
            syn_txt, "%-16s%-10s%-10s%-18s%s\n",
            "SYN Flow ID", "Source", "Target", "Start time (ns)", "Metadata"
    );

    fprintf(
            icmp_txt, "%-16s%-10s%-10s%-18s%s\n",
            "ICMP Flow ID", "Source", "Target", "Start time (ns)", "Metadata"
    );

    fprintf(
            icmp_txt, "%-16s%-10s%-10s%-18s%s\n",
            "UDP Flow ID", "Source", "Target", "Start time (ns)", "Metadata"
    );

    // Process each flow
    std::cout << "  > Writing log files line-by-line" << std::endl;
    std::cout << "  > Total flow entries to write... " << m_apps.size() << std::endl;
    uint32_t app_idx = 0;
    
    for (AttackFlowScheduleEntry& entry : m_schedule) {
        std::string metadata = entry.GetMetadata();
        

	//NEW
        if (metadata == "synflood") {
            // Write SYN flow in CSV format 
            fprintf(
                syn_csv, "%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%s\n",
                entry.GetAttackFlowId(), entry.GetFromNodeId(), entry.GetToNodeId(), 
                entry.GetStartTimeNs(), metadata.c_str()
            );

            // Write SYN flow in txt format 
            fprintf(
                syn_txt, "%-16" PRId64 "%-10" PRId64 "%-10" PRId64 "%-18" PRId64 "%s\n",
                entry.GetAttackFlowId(), entry.GetFromNodeId(), entry.GetToNodeId(),
                entry.GetStartTimeNs(), metadata.c_str()
            );
        }
	else if (metadata == "udpflood") {
            // Write UDP flow in CSV format 
            fprintf(
                udp_csv, "%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%s\n",
                entry.GetAttackFlowId(), entry.GetFromNodeId(), entry.GetToNodeId(), 
                entry.GetStartTimeNs(), metadata.c_str()
            );

            // Write UDP flow in txt format 
            fprintf(
                udp_txt, "%-16" PRId64 "%-10" PRId64 "%-10" PRId64 "%-18" PRId64 "%s\n",
                entry.GetAttackFlowId(), entry.GetFromNodeId(), entry.GetToNodeId(),
                entry.GetStartTimeNs(), metadata.c_str()
            );
	}
	else if (metadata == "icmpflood") {
            // Write ICMP flow in CSV format 
            fprintf(
                icmp_csv, "%" PRId64 ",%" PRId64 ",%" PRId64 ",%" PRId64 ",%s\n",
                entry.GetAttackFlowId(), entry.GetFromNodeId(), entry.GetToNodeId(), 
                entry.GetStartTimeNs(), metadata.c_str()
            );

            // Write ICMP flow in txt format 
            fprintf(
                icmp_txt, "%-16" PRId64 "%-10" PRId64 "%-10" PRId64 "%-18" PRId64 "%s\n",
                entry.GetAttackFlowId(), entry.GetFromNodeId(), entry.GetToNodeId(),
                entry.GetStartTimeNs(), metadata.c_str()
            );
	}
	else {
		std::cout<<"nada"<<std::endl;
        }
        
        // Increment app_idx for each flow, whether TCP or SYN
        app_idx += 1;
    }

    // Close all files
    std::cout << "  > Closing flow log files:" << std::endl;
    fclose(syn_csv);
    std::cout << "    >> Closed: " << m_syn_flows_csv_filename << std::endl;
    fclose(syn_txt);
    std::cout << "    >> Closed: " << m_syn_flows_txt_filename << std::endl;

    fclose(icmp_csv);
    std::cout << "    >> Closed: " << m_icmp_flows_csv_filename << std::endl;
    fclose(icmp_txt);
    std::cout << "    >> Closed: " << m_icmp_flows_txt_filename << std::endl;

    fclose(udp_csv);
    std::cout << "    >> Closed: " << m_udp_flows_csv_filename << std::endl;
    fclose(udp_txt);
    std::cout << "    >> Closed: " << m_udp_flows_txt_filename << std::endl;

    // Register completion
    std::cout << "  > Flow log files have been written" << std::endl;
    m_basicSimulation->RegisterTimestamp("Write flow log files");

    std::cout << std::endl;
}

}
