/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "udp-attack-application.h"
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


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("UdpAttackApplication");

NS_OBJECT_ENSURE_REGISTERED (UdpAttackApplication);



TypeId
UdpAttackApplication::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::UdpAttackApplication")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<UdpAttackApplication> ()
    .AddAttribute("SocketType",
                  "Type of socket to use (e.g., ns3::UdpSocketFactory)",
                   StringValue("ns3::UdpSocketFactory"),
                   MakeStringAccessor(&UdpAttackApplication::m_socketType),
                   MakeStringChecker())

    .AddAttribute ("Remote", "The target address",
                   AddressValue (),
                   MakeAddressAccessor (&UdpAttackApplication::m_peer),
                   MakeAddressChecker ())

    .AddAttribute ("FlowId", "Flow identifier",
                   UintegerValue (0),
                   MakeUintegerAccessor (&UdpAttackApplication::m_flowId),
                   MakeUintegerChecker<uint32_t> ())

    .AddAttribute ("UdpInterval", "The time between UDP packets",
                   TimeValue (NanoSeconds(1000000000)),
                   MakeTimeAccessor (&UdpAttackApplication::m_interval),
                   MakeTimeChecker())

    .AddAttribute ("EnableLogging", "Enable attack metrics logging",
                   BooleanValue (true),
                   MakeBooleanAccessor (&UdpAttackApplication::m_enableLogging),
                   MakeBooleanChecker ())

    .AddAttribute ("BaseLogsDir", "Base directory for logs",
                   StringValue (""),
                   MakeStringAccessor (&UdpAttackApplication::m_baseLogsDir),
                   MakeStringChecker ())

    .AddAttribute("Protocol",
                  "Protocol number (17 for UDP)",
                  UintegerValue(17),  
                  MakeUintegerAccessor(&UdpAttackApplication::m_protocol),
                  MakeUintegerChecker<uint8_t>())
     
     .AddAttribute("AttackDuration",
                   "Duration of the attack",
                   TimeValue(NanoSeconds(10000000000)),
                   MakeTimeAccessor(&UdpAttackApplication::m_attackDuration),
                   MakeTimeChecker());
    return tid;

}


UdpAttackApplication::UdpAttackApplication ()
  : m_protocol(17),            // UDP protocol
    m_count(0),                // Initialize counter
    m_flowId(0),               // Default flow ID
    m_running(false),          // Not running initially
    m_socket(0),               // No socket yet
    m_socketType("ns3::UdpSocketFactory"),
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

UdpAttackApplication::~UdpAttackApplication ()
{
  NS_LOG_FUNCTION (this);
}


void
UdpAttackApplication::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_socket = 0;
  Application::DoDispose ();
}


void
UdpAttackApplication::StopApplication(void)
{
  NS_LOG_FUNCTION(this);
  m_running=false; 
  NS_LOG_FUNCTION("----------CLOSING UDP ATTACKER APP------------"<<Simulator::Now());

  if (m_socket !=0)
  {
	  m_socket->Close();
	  m_socket->SetRecvCallback(MakeNullCallback <void, Ptr <Socket>>());
	  Simulator::Cancel(m_sendEvent);
	  NS_LOG_INFO("UdpAttackApplication - Flow "<< m_flowId << " stopped: ""\nTotal UDPs sent: "<<m_count);
  }
}

void
UdpAttackApplication::StartApplication (void)
{
    NS_LOG_FUNCTION (this);
    
    if (m_attackDuration == Seconds(0))
    {
        NS_LOG_ERROR("Attack duration not set for ICMP flood attack");
        return;
    }
    
    if (!m_socket)
    {
        // 1. Create UDP socket 

        NS_LOG_INFO ("Creating UDP socket for UDP attack");

	Ptr<Node> node=GetNode();
        Ptr<NetDevice> netDevice = node->GetDevice(1);

	m_socket = Socket::CreateSocket (node, TypeId::LookupByName(m_socketType));
	NS_ASSERT (m_socket != 0);

        // Debug interfaces 
        Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();
        NS_LOG_INFO("Node " << GetNode()->GetId() << " has " << GetNode()->GetNDevices() << " interfaces");

	/* COMMENTED FOR SHORT LOGS
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

	//Direct Connect  - (without bind)
	m_socket->Connect(InetSocketAddress(m_dstAddr,0));
	if (!m_socket){
		NS_LOG_ERROR("Error: rawSocket es nullptr");
		return;
	}
	

    }

    if (m_enableLogging)
    {
        NS_LOG_INFO ("UdpAttackApplication - Flow " << m_flowId << " initializing logs");
        std::string logFile = m_baseLogsDir + "/udp_attack_" + std::to_string(m_flowId) + "_metrics.csv";
        std::ofstream ofs(logFile);
        ofs << "flow_id,timestamp,udps_sent" << std::endl;
        ofs.close();
        NS_LOG_INFO ("Attack metrics will be logged to: " << logFile);

    }
    m_running = true;
    m_count = 0;
    SendUdp ();
}



void UdpAttackApplication::SendUdp(void)
{
   NS_LOG_FUNCTION(this);
  
   if (!m_running) return;
 
   Ptr<Packet> packet = Create<Packet>(1472);

   
   NS_LOG_INFO("UdpAttackApplication - Flow " << m_flowId << 
               " sending UDP packet #" << m_count << 
               "\nFrom: " << m_srcAddr << 
               "\nTo: " << m_dstAddr );

   NS_LOG_INFO("UdpAttackApplication - Flow " << m_flowId << 
               " sending UDP packet #" << m_count);


   //5.Random destination port
   // Each UDP packet is using a different destination port number
   Ptr<UniformRandomVariable> randPort = CreateObject<UniformRandomVariable>();
   randPort->SetAttribute("Min", DoubleValue(1024));  // Rango mínimo (evitar puertos reservados < 1024)
   randPort->SetAttribute("Max", DoubleValue(65535)); // Rango máximo
	
   uint16_t dstPort = static_cast<uint16_t>(randPort->GetInteger());
   NS_LOG_INFO("dstPort randomly obtained: "<<dstPort<<"\n");


   // 6. Send packet
   int result = m_socket->SendTo(packet, 0, InetSocketAddress(m_dstAddr,dstPort));
   if (result >= 0) {
           NS_LOG_INFO("  UDP packet #" << m_count << " sent successfully at "<<Simulator::Now().GetNanoSeconds()<<" s ");
           m_count++;
           if (m_enableLogging) {
               InsertAttackLog(Simulator::Now().GetNanoSeconds(), m_count);
           }
   }
   else {
           NS_LOG_ERROR("Failed to send UDP packet, error code: " << m_socket->GetErrno());
        }
  

   // 7. Schedule next sending
   m_sendEvent = Simulator::Schedule(m_interval, &UdpAttackApplication::SendUdp, this);

}



void
UdpAttackApplication::InsertAttackLog (int64_t timestamp, uint32_t udps_sent)
{

  std::string logFile = m_baseLogsDir + "/udp_attack_" + std::to_string(m_flowId) + "_metrics.csv";
  std::ofstream ofs(logFile, std::ofstream::out | std::ofstream::app);
  ofs << m_flowId << "," << timestamp << "," << udps_sent << std::endl;
  ofs.close();

}



} // Namespace ns3
