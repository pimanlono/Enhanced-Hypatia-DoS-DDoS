/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */



#include "icmp-attack-application.h"
#include "ns3/log.h"
#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/socket.h"
#include "ns3/string.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/exp-util.h"
#include <fstream>

//NEW

#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-address.h"
#include "ns3/ipv4-static-routing.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-routing-helper.h"

#include "ns3/tcp-option-ts.h"
#include "ns3/tcp-option.h"
#include "ns3/tcp-option-winscale.h"

//PILAR2703
#include "ns3/tcp-flow-sink.h"

#include "ns3/icmpv4.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("IcmpAttackApplication");

NS_OBJECT_ENSURE_REGISTERED (IcmpAttackApplication);


TypeId

IcmpAttackApplication::GetTypeId (void)

{

  static TypeId tid = TypeId ("ns3::IcmpAttackApplication")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<IcmpAttackApplication> ()
    .AddAttribute("SocketType",
                  "Type of socket to use (e.g., ns3::Ipv4RawSocketFactory)",
                   StringValue("ns3::Ipv4RawSocketFactory"),
                   MakeStringAccessor(&IcmpAttackApplication::m_socketType),
                   MakeStringChecker())

    .AddAttribute ("Remote", "The target address",
                   AddressValue (),
                   MakeAddressAccessor (&IcmpAttackApplication::m_peer),
                   MakeAddressChecker ())

    .AddAttribute ("FlowId", "Flow identifier",
                   UintegerValue (0),
                   MakeUintegerAccessor (&IcmpAttackApplication::m_flowId),
                   MakeUintegerChecker<uint32_t> ())

    .AddAttribute ("IcmpInterval", "The time between SYNs",
                   TimeValue (NanoSeconds(1000000000)),
                   MakeTimeAccessor (&IcmpAttackApplication::m_interval),
                   MakeTimeChecker())

    .AddAttribute ("EnableLogging", "Enable attack metrics logging",
                   BooleanValue (true),
                   MakeBooleanAccessor (&IcmpAttackApplication::m_enableLogging),
                   MakeBooleanChecker ())

    .AddAttribute ("BaseLogsDir", "Base directory for logs",
                   StringValue (""),
                   MakeStringAccessor (&IcmpAttackApplication::m_baseLogsDir),
                   MakeStringChecker ())

    .AddAttribute("Protocol",
                  "Protocol number (1 for TCP)",
                  UintegerValue(1),  // TCP
                  MakeUintegerAccessor(&IcmpAttackApplication::m_protocol),
                  MakeUintegerChecker<uint8_t>())
     
     .AddAttribute("AttackDuration",
                   "Duration of the attack",
                   TimeValue(NanoSeconds(10000000000)),
                   MakeTimeAccessor(&IcmpAttackApplication::m_attackDuration),
                   MakeTimeChecker());
    return tid;

}


IcmpAttackApplication::IcmpAttackApplication ()

  : m_protocol(1),              // TCP protocol
    m_count(0),                // Initialize counter
    m_flowId(0),               // Default flow ID
    m_running(false),          // Not running initially
    m_socket(0),               // No socket yet
    m_socketType("ns3::Ipv4RawSocketFactory"),
    m_interval(1000000000),
    m_attackDuration(10000000000),
    m_enableLogging(true),
    m_portRng(CreateObject<UniformRandomVariable> ()),
    m_seqRng(CreateObject<UniformRandomVariable> ())

{

  NS_LOG_FUNCTION (this);

  m_portRng->SetAttribute ("Min", DoubleValue (1024));
  m_portRng->SetAttribute ("Max", DoubleValue (65535));
  m_seqRng->SetAttribute ("Min", DoubleValue (0));
  m_seqRng->SetAttribute ("Max", DoubleValue (4294967295));

}



IcmpAttackApplication::~IcmpAttackApplication ()

{

  NS_LOG_FUNCTION (this);

}



void
IcmpAttackApplication::DoDispose (void)
{

  NS_LOG_FUNCTION (this);
  m_socket = 0;
  Application::DoDispose ();

}



void
IcmpAttackApplication::StopApplication(void)
{
  NS_LOG_FUNCTION(this);
  m_running=false; 
  NS_LOG_FUNCTION("----------CLOSING ICMP ATTACKER APP------------"<<Simulator::Now());

  if (m_socket !=0)
  {
	  m_socket->Close();
	  m_socket->SetRecvCallback(MakeNullCallback <void, Ptr <Socket>>());
	  Simulator::Cancel(m_sendEvent);
	  NS_LOG_INFO("IcmpAttackApplication - Flow "<< m_flowId << " stopped: ""\nTotal ICMPs sent: "<<m_count);
  }

}

void
IcmpAttackApplication::StartApplication (void)

{
    NS_LOG_FUNCTION (this);
    
    //10-12 new : Verificar que se haya configurado un tiempo de parada válido
    if (m_attackDuration == Seconds(0))
    {
        NS_LOG_ERROR("Attack duration not set for ICMP flood attack");
        return;
    }
    
    if (!m_socket)
    {

        Ptr<Node> node=GetNode();
        Ptr<NetDevice> netDevice = node->GetDevice(1);

        // SEMANA SANTA. Para poder quitarlo de main_satnet.cc
        //0. Configure Static Rouring, required for RawSocket

        // Get and verify  Ipv4
        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        if (ipv4 == 0) {
                std::cout << "  > Error: Node " << node << " has no Ipv4" << std::endl;
                return;
        }

        // Create and assign static routing
        Ptr<Ipv4StaticRouting> staticRouting = CreateObject<Ipv4StaticRouting>();
        if (staticRouting == 0) {
                std::cout << "  > Error: Could not create static routing for node " << node << std::endl;
                return;
        }

        // Configure routing protocol
        ipv4->SetRoutingProtocol(staticRouting);

        // Add deffault Network Route 
        staticRouting->AddNetworkRouteTo(
                Ipv4Address("10.0.0.0"),
                Ipv4Mask("255.0.0.0"),
                Ipv4Address("0.0.0.0"),
                1
        );

        std::cout << "  > Configured static routing for attack node " << node << std::endl;
    


	    // 1. Create raw socket 

        NS_LOG_INFO ("Creating raw socket for ICMP flood attack");
	m_socket = Socket::CreateSocket (node, TypeId::LookupByName(m_socketType));
	NS_ASSERT (m_socket != 0);

	m_socket->SetAttribute("Protocol",UintegerValue(1));


        // Debug interfaces 
        NS_LOG_INFO("Node " << GetNode()->GetId() << " has " << GetNode()->GetNDevices() << " interfaces");

	/*COMMENTED FOR SHORT LOG
	for (uint32_t i = 0; i < GetNode()->GetNDevices(); i++) {
            std::stringstream interfaceInfo;
            interfaceInfo << "Interface " << i << ":\n";
            interfaceInfo << "  MAC: " << GetNode()->GetDevice(i)->GetAddress() << "\n";
            if (i < ipv4->GetNInterfaces()) {

                for (uint32_t j = 0; j < ipv4->GetNAddresses(i); j++) {
                    interfaceInfo << "  IP: " << ipv4->GetAddress(i, j).GetLocal();
                }

            }
            NS_LOG_INFO(interfaceInfo.str());

        }
	*/

        // 3. Save  IP destination 
        if (!InetSocketAddress::IsMatchingType(m_peer))
        {
            NS_FATAL_ERROR("Remote address is not Ipv4 type");
            return;
        }
        InetSocketAddress destAddr = InetSocketAddress::ConvertFrom(m_peer);
        m_dstAddr = destAddr.GetIpv4();

        // 4. Configure origin (interface 1)
        m_srcAddr = ipv4->GetAddress(1, 0).GetLocal();
        NS_LOG_INFO("Using source " << m_srcAddr << " for attack");

	//5. Bind para que establezca bien la ip origen
	m_socket->Bind(InetSocketAddress(m_srcAddr,0));


	//Connect directo - sin hacer bind
	//m_socket->Connect(InetSocketAddress(m_dstAddr,0));
	if (!m_socket){
		NS_LOG_ERROR("Error: rawSocket es nullptr");
		return;
	}

    }

    if (m_enableLogging)
    {
        NS_LOG_INFO ("IcmpAttackApplication - Flow " << m_flowId << " initializing logs");
        std::string logFile = m_baseLogsDir + "/icmp_attack_" + std::to_string(m_flowId) + "_metrics.csv";
        std::ofstream ofs(logFile);
        ofs << "flow_id,timestamp,icmps_sent" << std::endl;
        ofs.close();
        NS_LOG_INFO ("Attack metrics will be logged to: " << logFile);

    }
    m_running = true;
    m_count = 0;
    SendIcmp ();
}



void IcmpAttackApplication::SendIcmp(void)
{
   NS_LOG_FUNCTION(this);
  
   if (!m_running) return;

    Icmpv4Echo echoRequest;
    echoRequest.SetIdentifier(1);
    echoRequest.SetSequenceNumber(1);

    Icmpv4Header  icmpHeader;
    icmpHeader.SetType(Icmpv4Header::ICMPV4_ECHO);
    icmpHeader.SetCode(0);

   // 4. Create packet 
   Ptr<Packet> packet = Create<Packet>(1400);
   packet->AddHeader(echoRequest);
   packet->AddHeader(icmpHeader);

   /* 
   NS_LOG_INFO("IcmpAttackApplication - Flow " << m_flowId << 
               " sending ICMP packet #" << m_count << 
               "\nFrom: " << m_srcAddr << 
               "\nTo: " << m_dstAddr );
   */

   NS_LOG_INFO("IcmpAttackApplication - Flow " << m_flowId << 
               " sending ICMP packet #" << m_count); 
		

   //5. Send packet
   int result = m_socket->SendTo(packet, 0, InetSocketAddress(m_dstAddr));
   if (result >= 0) {
        NS_LOG_INFO("  ICMP packet #" << m_count << " sent successfully at "<<Simulator::Now().GetNanoSeconds()<<" s ");
        m_count++;
        if (m_enableLogging) {
           InsertAttackLog(Simulator::Now().GetNanoSeconds(), m_count);
        }
   }
   else {
        NS_LOG_ERROR("Failed to send ICMP packet, error code: " << m_socket->GetErrno());
   }

   // 7. Schedule next sending
   m_sendEvent = Simulator::Schedule(m_interval, &IcmpAttackApplication::SendIcmp, this);

}


void
IcmpAttackApplication::InsertAttackLog (int64_t timestamp, uint32_t icmps_sent)
{

  std::string logFile = m_baseLogsDir + "/icmp_attack_" + std::to_string(m_flowId) + "_metrics.csv";
  std::ofstream ofs(logFile, std::ofstream::out | std::ofstream::app);
  ofs << m_flowId << "," << timestamp << "," << icmps_sent << std::endl;
  ofs.close();

}



} // Namespace ns3
