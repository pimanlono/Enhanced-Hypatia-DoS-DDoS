/*
 * Copyright (c) 2020 ETH Zurich
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
 * Author: Simon               2020
 */
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

#include "ns3/basic-simulation.h"
#include "ns3/tcp-flow-scheduler.h"
#include "ns3/udp-burst-scheduler.h"
#include "ns3/pingmesh-scheduler.h"
#include "ns3/topology-satellite-network.h"
#include "ns3/tcp-optimizer.h"
#include "ns3/arbiter-single-forward-helper.h"
#include "ns3/ipv4-arbiter-routing-helper.h"
#include "ns3/gsl-if-bandwidth-helper.h"
#include "ns3/tcp-syn-flood-socket.h"
#include "ns3/log.h" //new inclusion
#include "ns3/internet-module.h"     //new inclusion
#include "ns3/tcp-socket-factory.h"  //new inclusion
#include "ns3/ipv4-l3-protocol.h"    //new inclusion
#include "ns3/tcp-l4-protocol.h"     //new inclusion
//12-11 NEW
#include "ns3/tcp-syn-flood-socket.h"
#include "ns3/tcp-syn-flood-socket-factory.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("MainSatnet"); //new


void RegisterAndConfigureSockets(Ptr<BasicSimulation> basicSimulation) {
    NS_LOG_FUNCTION_NOARGS();

    // 1. Registrar y verificar disponibilidad de tipos de socket
    TypeId synFloodId;
    TypeId tcpNewRenoId;
    TypeId tcpVegasId;

    bool hasSynFlood = TypeId::LookupByNameFailSafe("ns3::TcpSynFloodSocket", &synFloodId);
    bool hasNewReno = TypeId::LookupByNameFailSafe("ns3::TcpNewReno", &tcpNewRenoId);
    bool hasVegas = TypeId::LookupByNameFailSafe("ns3::TcpVegas", &tcpVegasId);

    // Registrar TcpSynFloodSocket y su factory si no están registrados
    if (!hasSynFlood) {
        NS_LOG_INFO("Registering TcpSynFloodSocket type");
        TcpSynFloodSocket::GetTypeId();
        TcpSynFloodSocketFactory::GetTypeId();
        hasSynFlood = true;
    }

    // 2. Log de tipos disponibles
    NS_LOG_INFO("Socket types available: "
                << "NewReno=" << (hasNewReno ? "yes" : "no") 
                << " Vegas=" << (hasVegas ? "yes" : "no")
                << " SynFlood=" << (hasSynFlood ? "yes" : "no"));

    // 3. Configurar ataque si está habilitado
    if (basicSimulation->GetConfigParamOrDefault("enable_syn_flood", "false") == "true") 
    {
        if (!hasSynFlood) {
            NS_FATAL_ERROR("SYN flood attack enabled but TcpSynFloodSocket not available!");
            return;
        }
        
        uint32_t attackRate = std::stoul(
            basicSimulation->GetConfigParamOrDefault("syn_flood_rate", "1000")
        );
        
        NS_LOG_INFO("SYN flood attack enabled with rate " << attackRate << " pkts/s");
        NS_LOG_INFO("Verified attack rate configuration: " << attackRate << " pkts/s");
    }
    else 
    {
        // 4. Solo informar del tipo de socket que se usará para flujos normales
        std::string legitSocketType = basicSimulation->GetConfigParamOrFail("tcp_socket_type");
        NS_LOG_INFO("Normal TCP flows will use socket type: ns3::" << legitSocketType);
    }
}

int main(int argc, char *argv[]) {
    // No buffering of printf
    setbuf(stdout, nullptr);

    // Retrieve run directory
    CommandLine cmd;
    std::string run_dir = "";
    cmd.Usage("Usage: ./waf --run=\"main_satnet --run_dir='<path/to/run/directory>'\"");
    cmd.AddValue("run_dir",  "Run directory", run_dir);
    cmd.Parse(argc, argv);
    if (run_dir.compare("") == 0) {
        printf("Usage: ./waf --run=\"main_satnet --run_dir='<path/to/run/directory>'\"");
        return 0;
    }

    // Load basic simulation environment
    Ptr<BasicSimulation> basicSimulation = CreateObject<BasicSimulation>(run_dir);

    
    // Setting socket type
    RegisterAndConfigureSockets(basicSimulation);
   
	
    // Optimize TCP
    TcpOptimizer::OptimizeBasic(basicSimulation);

    // Read topology, and install routing arbiters
    Ptr<TopologySatelliteNetwork> topology = CreateObject<TopologySatelliteNetwork>(basicSimulation, Ipv4ArbiterRoutingHelper());
    
    //9-11 NEW
    //Verificar la fábrica de sockets en cada nodo
    NodeContainer nodes = topology->GetNodes();
    for (uint32_t i = 0; i < nodes.GetN(); ++i) {
        Ptr<Node> node = nodes.Get(i);
        Ptr<TcpSocketFactory> factory = node->GetObject<TcpSocketFactory>();
        if (!factory) {
            NS_FATAL_ERROR("Node " << i << " does not have TcpSocketFactory installed");
        }
    }
    
    
    ArbiterSingleForwardHelper arbiterHelper(basicSimulation, topology->GetNodes());
    GslIfBandwidthHelper gslIfBandwidthHelper(basicSimulation, topology->GetNodes());

    // Schedule flows
    TcpFlowScheduler tcpFlowScheduler(basicSimulation, topology);
   
    
    // Schedule UDP bursts
    UdpBurstScheduler udpBurstScheduler(basicSimulation, topology);

    // Schedule pings
    PingmeshScheduler pingmeshScheduler(basicSimulation, topology);

    // Run simulation
    basicSimulation->Run();

    // Write flow results
    tcpFlowScheduler.WriteResults();

    // Write UDP burst results
    udpBurstScheduler.WriteResults();

    // Write pingmesh results
    pingmeshScheduler.WriteResults();

    // Collect utilization statistics
    topology->CollectUtilizationStatistics();

    // Finalize the simulation
    basicSimulation->Finalize();

    return 0;
}
