/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */



#include "syn-attack-application.h"
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



namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("SynAttackApplication");

NS_OBJECT_ENSURE_REGISTERED (SynAttackApplication);



TypeId

SynAttackApplication::GetTypeId (void)

{

  static TypeId tid = TypeId ("ns3::SynAttackApplication")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<SynAttackApplication> ()
    .AddAttribute("SocketType",
                  "Type of socket to use (e.g., ns3::Ipv4RawSocketFactory)",
                   StringValue("ns3::Ipv4RawSocketFactory"),
                   MakeStringAccessor(&SynAttackApplication::m_socketType),
                   MakeStringChecker())

    .AddAttribute ("Remote", "The target address",
                   AddressValue (),
                   MakeAddressAccessor (&SynAttackApplication::m_peer),
                   MakeAddressChecker ())

    .AddAttribute ("FlowId", "Flow identifier",
                   UintegerValue (0),
                   MakeUintegerAccessor (&SynAttackApplication::m_flowId),
                   MakeUintegerChecker<uint32_t> ())

    .AddAttribute ("SynInterval", "The time between SYNs",
                   TimeValue (NanoSeconds(1000000)),
                   MakeTimeAccessor (&SynAttackApplication::m_interval),
                   MakeTimeChecker())

    .AddAttribute ("EnableLogging", "Enable attack metrics logging",
                   BooleanValue (true),
                   MakeBooleanAccessor (&SynAttackApplication::m_enableLogging),
                   MakeBooleanChecker ())

    .AddAttribute ("BaseLogsDir", "Base directory for logs",
                   StringValue (""),
                   MakeStringAccessor (&SynAttackApplication::m_baseLogsDir),
                   MakeStringChecker ())

    .AddAttribute("Protocol",
                  "Protocol number (6 for TCP)",
                  UintegerValue(6),  // TCP
                  MakeUintegerAccessor(&SynAttackApplication::m_protocol),
                  MakeUintegerChecker<uint8_t>())
     
     .AddAttribute("AttackDuration",
                   "Time to stop sending SYNs",
                   TimeValue(NanoSeconds(10000000000)),
                   MakeTimeAccessor(&SynAttackApplication::m_attackDuration),
                   MakeTimeChecker());
    return tid;

}


SynAttackApplication::SynAttackApplication ()

  : m_protocol(6),              // TCP protocol
    m_dstPort(1024),              // Default port
    m_srcPort(0),
    m_count(0),                // Initialize counter
    m_flowId(0),               // Default flow ID
    m_running(false),          // Not running initially
    m_socket(0),               // No socket yet
    m_socketType("ns3::Ipv4RawSocketFactory"),
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



SynAttackApplication::~SynAttackApplication ()

{

  NS_LOG_FUNCTION (this);

}



void
SynAttackApplication::DoDispose (void)
{

  NS_LOG_FUNCTION (this);
  m_socket = 0;
  Application::DoDispose ();

}



void
SynAttackApplication::StopApplication(void)
{
  NS_LOG_FUNCTION(this);
  m_running=false; //pilar paellas
  NS_LOG_FUNCTION("----------pilar: CLOSING ATTACKER APP------------"<<Simulator::Now());
/*
  if (m_socket !=0)
  {
	  m_socket->Close();
	  m_socket->SetRecvCallback(MakeNullCallback <void, Ptr <Socket>>());
	  Simulator::Cancel(m_sendEvent);
	  NS_LOG_INFO("SynAttackApplication - Flow "<< m_flowId << " stopped:""\nTotal SYNs sent: "<<m_count);
  }
*/
}

//PILAR2703
bool TcpPacketFilter(Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol, const Address &from)
{
    // Comprobar si el protocolo es TCP (0x06 en IPv4)
    if (protocol == 0x0800) // IPv4 Ethertype
    {
        Ipv4Header ipv4Header;
        packet->PeekHeader(ipv4Header); // Extraer el encabezado IPv4

        if (ipv4Header.GetProtocol() == 6) // 6 = TCP
        {
            NS_LOG_INFO("Bloqueando paquete TCP desde " << ipv4Header.GetSource());
            return false; // Devolver false para descartar el paquete
        }
    }
    return true; // Dejar pasar los demás paquetes
}




//PILAR2703: para tratar de filtrar el tráfico TCP entrente al nodo atacante
void ConfigureTcpBlocking(Ptr<Node> node)
{
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>(); // Obtener el protocolo IPv4 del nodo
    if (ipv4)
    {
        Ptr<NetDevice> device = node->GetDevice(1); // El que usamos, el 0 es 127.0.0.1
        if (device)
        {
            device->SetReceiveCallback(MakeCallback(&TcpPacketFilter)); // Asignamos el filtro
            NS_LOG_INFO("Filtro TCP activado en el nodo");
        }
    }
}



void
SynAttackApplication::StartApplication (void)

{
    NS_LOG_FUNCTION (this);
    
    //10-12 new : Verificar que se haya configurado un tiempo de parada válido
    if (m_attackDuration == Seconds(0))
    {
        NS_LOG_ERROR("Stop time not set for SYN flood attack");
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

        NS_LOG_INFO ("Creating raw socket for SYN flood attack");

	//PILAR
	ConfigureTcpBlocking(node);

	m_socket = Socket::CreateSocket (node, TypeId::LookupByName(m_socketType));
	
	NS_ASSERT (m_socket != 0);
        m_socket->SetAttribute("IpHeaderInclude", BooleanValue(true));
        NS_LOG_INFO("IpHeaderInclude attribute set to true.");


        // Debug interfaces 
        //Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();
        NS_LOG_INFO("Node " << GetNode()->GetId() << " has " << GetNode()->GetNDevices() << " interfaces");

	// COMMENTED FOR SHORT LOGS
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
	

        // 3. Save  IP and port destination 
        if (!InetSocketAddress::IsMatchingType(m_peer))
        {
            NS_FATAL_ERROR("Remote address is not Ipv4 type");
            return;
        }

        InetSocketAddress destAddr = InetSocketAddress::ConvertFrom(m_peer);
        m_dstAddr = destAddr.GetIpv4();
        m_dstPort = destAddr.GetPort();
        NS_ASSERT_MSG(m_dstPort != 0, "Target port cannot be 0!");

        // 4. Configure origin (int 1)
        m_srcAddr = ipv4->GetAddress(1, 0).GetLocal();
        NS_LOG_INFO("Using source " << m_srcAddr << " for attack");
        NS_LOG_INFO("Target is " << m_dstAddr << ":" << m_dstPort);

        // 5.Direct connect 
	//
	//m_socket->Connect(InetSocketAddress(m_dstAddr,m_dstPort));

    }

    if (m_enableLogging)
    {
        NS_LOG_INFO ("SynAttackApplication - Flow " << m_flowId << " initializing logs");
        std::string logFile = m_baseLogsDir + "/syn_attack_" + std::to_string(m_flowId) + "_metrics.csv";
        std::ofstream ofs(logFile);
        ofs << "flow_id,timestamp,syns_sent" << std::endl;
        ofs.close();
        NS_LOG_INFO ("Attack metrics will be logged to: " << logFile);

    }
    m_running = true;
    m_count = 0;
    SendSyn ();
}


//NEW VERSION OF SENDSYN

void SynAttackApplication::SendSyn(void)
{
   NS_LOG_FUNCTION(this);
  
   if (!m_running) return;


   // 1. Verify destination port 
   NS_ASSERT_MSG(m_dstPort != 0, "Destination port cannot be 0!");

   // 2. Create TCP header
   
   // Each SYN is using a different source port number
   Ptr<UniformRandomVariable> randPort = CreateObject<UniformRandomVariable>();
   randPort->SetAttribute("Min", DoubleValue(1024));  // Rango mínimo (evitar puertos reservados < 1024)
   randPort->SetAttribute("Max", DoubleValue(65535)); // Rango máximo
	
   m_srcPort = static_cast<uint16_t>(randPort->GetInteger());
   NS_LOG_INFO("srcPort randomly obtained: "<<m_srcPort<<"\n");

   TcpHeader tcpHeader;
   tcpHeader.SetSourcePort(m_srcPort);
   tcpHeader.SetDestinationPort(m_dstPort);
   tcpHeader.SetFlags(TcpHeader::SYN);
   //tcpHeader.SetSequenceNumber(SequenceNumber32(m_seqRng->GetInteger()));
   //PILAR paellas
   tcpHeader.SetSequenceNumber(SequenceNumber32(0));
   Ptr<TcpOptionTS> tsOption=CreateObject<TcpOptionTS>();
   tsOption->SetTimestamp(Simulator::Now().GetMilliSeconds());
   tsOption->SetEcho(0);
   tcpHeader.AppendOption(tsOption);

   // Opción Window Scaling (WSCALE)
   Ptr<TcpOptionWinScale> wsOption = CreateObject<TcpOptionWinScale>();
   wsOption->SetScale(10);  // Establece el factor de escalado de la ventana (puedes ajustarlo)
   tcpHeader.AppendOption(wsOption);

   // Opción SACK Permitted
   Ptr<TcpOptionSackPermitted> sackOption = CreateObject<TcpOptionSackPermitted>();
   tcpHeader.AppendOption(sackOption);


   NS_LOG_INFO("Cabecera TCP creada");

   // 3. Create IP header 
   Ipv4Header ipHeader;
   ipHeader.SetSource(m_srcAddr);
   ipHeader.SetDestination(m_dstAddr);
   ipHeader.SetProtocol(6);
   ipHeader.SetTtl(64);
   ipHeader.SetPayloadSize(tcpHeader.GetSerializedSize());
   NS_LOG_INFO("Cabecera IP creada");

   // 4. Create packet 
   Ptr<Packet> packet = Create<Packet>(0);
   packet->AddHeader(tcpHeader);
   packet->AddHeader(ipHeader);

   /* 
   NS_LOG_INFO("SynAttackApplication - Flow " << m_flowId << 
               " sending SYN packet #" << m_count << 
               "\nFrom: " << m_srcAddr << ":" << m_srcPort << 
               "\nTo: " << m_dstAddr << ":" << m_dstPort);
   */
   NS_LOG_INFO("SynAttackApplication - Flow " << m_flowId << 
               " sending SYN packet #" << m_count); 

   /*
   // 5. Configure static routing before send it  
   Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();


   Ipv4StaticRoutingHelper staticRoutingHelper;
   Ptr<Ipv4StaticRouting> staticRouting = staticRoutingHelper.GetStaticRouting(ipv4);

   if (staticRouting == nullptr) {
       NS_LOG_UNCOND("StaticRouting object is null! Check if ipv4RoutingHelper is correctly configured.");
   }
   else {
       // Show configured routes for debugging 
       for (uint32_t i = 0; i < staticRouting->GetNRoutes(); i++) {
           Ipv4RoutingTableEntry route = staticRouting->GetRoute(i);
           Ipv4Address dest = route.GetDest();
           Ipv4Address gateway = route.GetGateway();
           uint32_t interface = route.GetInterface();
           Ptr<NetDevice> device = ipv4->GetNetDevice(interface);
           
           NS_LOG_INFO("  Ruta #" << i << " Destino: " << dest
                       << " Gateway: " << gateway 
                       << " Interfaz salida: " << interface
                       << " Dispositivo salida: " << device);
       }
   }
   */

   // 6. Send packeti
   //Si se hace bind
   //Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();
   //Socket::SocketErrno sockerr;
   //Ptr<Ipv4Route> route=ipv4->GetRoutingProtocol()->RouteOutput(packet,ipHeader,nullptr,sockerr);
   //Ptr<NetDevice> outDevice=GetNode()->GetDevice(1); 
   //m_socket->BindToNetDevice(outDevice); 
   //m_socket->Bind(InetSoc*/ketAddress(Ipv4Address::GetAny(), 0));
   //m_socket->BindToNetDevice(nullptr);
   int result = m_socket->SendTo(packet, 0, InetSocketAddress(m_dstAddr, m_dstPort));
   // Si no se hace bind
   
   //int result = m_socket->Send(packet);

   if (result >= 0) {
       NS_LOG_INFO("  SYN packet #" << m_count << " sent successfully");
       m_count++;
       if (m_enableLogging) {
           InsertAttackLog(Simulator::Now().GetNanoSeconds(), m_count);
       }
   }
   else {
       NS_LOG_ERROR("Failed to send SYN packet, error code: " << m_socket->GetErrno());
   }
   

   // 7. Schedule next sending
   m_sendEvent = Simulator::Schedule(m_interval, &SynAttackApplication::SendSyn, this);

}

void
SynAttackApplication::InsertAttackLog (int64_t timestamp, uint32_t syns_sent)
{

  std::string logFile = m_baseLogsDir + "/syn_attack_" + std::to_string(m_flowId) + "_metrics.csv";
  std::ofstream ofs(logFile, std::ofstream::out | std::ofstream::app);
  ofs << m_flowId << "," << timestamp << "," << syns_sent << std::endl;
  ofs.close();

}



} // Namespace ns3
