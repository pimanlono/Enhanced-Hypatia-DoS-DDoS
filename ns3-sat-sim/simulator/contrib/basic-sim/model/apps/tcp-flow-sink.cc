#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/tcp-socket-factory.h"
#include "tcp-flow-sink.h"
#include "ns3/tcp-socket-base.h"
#include <fstream>

//NEW: 
namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("TcpFlowSink");
NS_OBJECT_ENSURE_REGISTERED (TcpFlowSink);

TypeId
TcpFlowSink::GetTypeId (void)
{
 static TypeId tid = TypeId ("ns3::TcpFlowSink")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<TcpFlowSink> ()
    .AddAttribute ("Local", "The Address on which to Bind the rx socket.",
                   AddressValue (),
                   MakeAddressAccessor (&TcpFlowSink::m_local),
                   MakeAddressChecker ())
    .AddAttribute ("Protocol", "The type id of the protocol to use for the rx socket.",
                   TypeIdValue (TcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&TcpFlowSink::m_tid),
                   MakeTypeIdChecker ())
    .AddAttribute ("BaseLogsDir", "Base directory for logs",
                   StringValue (""),
                   MakeStringAccessor (&TcpFlowSink::m_baseLogsDir),
                   MakeStringChecker ())
    //NEW 15-12            
    .AddAttribute ("MaxSynBacklog", "Maximum number of half-open connections allowed",
                   UintegerValue (1280),
                   MakeUintegerAccessor (&TcpFlowSink::m_maxSynBacklog),
                   MakeUintegerChecker<uint32_t> ())           
  ;
  return tid;
}


TcpFlowSink::TcpFlowSink ()
 : m_socket (0),
//PILAR
   m_totalRx(0),
   m_synReceived (0),
   m_connectionsEstablished (0),
   //NEW 15-12
   m_maxSynBacklog (1280),
   m_droppedSyns (0)
{
 NS_LOG_FUNCTION (this);
}

TcpFlowSink::~TcpFlowSink()
{
 NS_LOG_FUNCTION (this);
 m_socket = 0;
}

void TcpFlowSink::DoDispose (void)
{
 NS_LOG_FUNCTION (this);
 Application::DoDispose ();
}


void TcpFlowSink::StartApplication (void)
{
 NS_LOG_FUNCTION (this<< "StartApplication en tcp_flow_sink");
 NS_LOG_INFO(this<< "StartApplication en tcp_flow_sink"); 
 if (!m_socket)
 {
     m_socket = Socket::CreateSocket (GetNode(), m_tid);
     m_socket->Bind (m_local);
     m_socket->Listen ();
     m_socket->ShutdownSend ();
     
     
     // Setting up callbacks using the new functions
     //m_socket->SetRecvCallback (MakeCallback (&TcpFlowSink::HandleRead, this));
     m_socket->SetAcceptCallback (
        MakeCallback (&TcpFlowSink::HandlePreConnectionCallback, this),  // Pre-con
        MakeCallback (&TcpFlowSink::HandleFullConnectionCallback, this)  // Completed con
     );
     
    
 }
     std::string logFile = m_baseLogsDir + "/connection_attempts.csv"; 
     std::ofstream ofs(logFile);
     // Updated CSV headers
     //ofs << "timestamp,connection_type,syn_count,established_count,source_ip" << std::endl;
     ofs << "timestamp,connection_type,syn_count,established_count,backlog_size,dropped_syns,source_ip" << std::endl;
     ofs.close();
     NS_LOG_INFO ("Connection logging enabled - TcpFlowSink: " << logFile); 
}


void TcpFlowSink::StopApplication ()
{
 NS_LOG_FUNCTION (this);
 CloseAllSockets();
 
}

/*
bool
TcpFlowSink::HandlePreConnectionCallback (Ptr<Socket> socket, const Address& from)
{
  
  // Convert the address correctly
  InetSocketAddress inetFrom = InetSocketAddress::ConvertFrom(from);
    
  // Increment SYN counter here
  m_synReceived++;
  m_halfOpenSockets.push_back(socket);
   
  NS_LOG_INFO("[TcpFlowSink] Pre-connection callback from " << inetFrom.GetIpv4() << ":" << inetFrom.GetPort());
  NS_LOG_INFO("TcpFlowSink statistics:" 
                << "\n  Total SYNs received: " << m_synReceived
                << "\n  Connections established: " << m_connectionsEstablished);

  
  LogConnectionAttempt(false,from); // Log connection attempt 
  return true;
}*/


bool
TcpFlowSink::HandlePreConnectionCallback (Ptr<Socket> socket, const Address& from)
{
  // Convertir dirección para logging
  InetSocketAddress inetFrom = InetSocketAddress::ConvertFrom(from);
  NS_LOG_INFO(" --->HandlePreconnection address desde from: "<<inetFrom.GetIpv4()<<" port: "<<inetFrom.GetPort());


  Address peerAddress;
  socket->GetSockName(peerAddress);
  InetSocketAddress pa=InetSocketAddress::ConvertFrom(peerAddress);
  NS_LOG_INFO(" --->HandlePreconnection address desde socket: "<<pa.GetIpv4()<<" port: "<<pa.GetPort());
  NS_LOG_INFO(" --->socket : "<<socket);

  // Verificar si el backlog está lleno
  if (m_halfOpenSockets.size() >= m_maxSynBacklog) {
    NS_LOG_WARN("Backlog is full (" << m_maxSynBacklog << " connections). Discarding SYN from " 
                 << inetFrom.GetIpv4());
    m_droppedSyns++; 
    LogConnectionAttempt(false, from, true); // true indica rechazado
    return false;  // Rechazar la conexión
  }

  // Contabilizar el SYN y añadir a conexiones pendientes
  m_synReceived++;
 
  NS_LOG_INFO("Pilar: tam m_halfOpenSockets antes de añadir"<< m_halfOpenSockets.size()<<" socket "<<socket);
  //m_halfOpenSockets.push_back(socket);
  m_halfOpenSockets.push_back(from);
  NS_LOG_INFO("Pilar: tam m_halfOpenSockets despues de añadir"<< m_halfOpenSockets.size());

 
  NS_LOG_INFO("[TcpFlowSink] Pre-connection callback from " << inetFrom.GetIpv4() << 
              ". Actual Backlog: " << m_halfOpenSockets.size());
  NS_LOG_INFO("TcpFlowSink statistics:" 
                << "\n  Total SYNs received: " << m_synReceived
                << "\n  Connections established: " << m_connectionsEstablished);
  LogConnectionAttempt(false, from, false);
  return true;
}




/*
void 
TcpFlowSink::HandleFullConnectionCallback(Ptr<Socket> socket, const Address& from)
{
    NS_LOG_INFO("Full connection established from " << InetSocketAddress::ConvertFrom(from).GetIpv4());
    m_halfOpenSockets.remove(socket);
    m_socketList.push_back(socket);
    m_connectionsEstablished++;
    
    // Only for connections that completed the handshake:
    socket->SetRecvCallback(MakeCallback(&TcpFlowSink::HandleRead, this));
    socket->SetCloseCallbacks(
        MakeCallback(&TcpFlowSink::HandlePeerClose, this),
        MakeCallback(&TcpFlowSink::HandlePeerError, this)
    );
    
    LogConnectionAttempt(true,from); // Connection established log
}*/


void 
TcpFlowSink::HandleFullConnectionCallback(Ptr<Socket> socket, const Address& from)
{
  InetSocketAddress inetFrom = InetSocketAddress::ConvertFrom(from);
    
  // Al completarse el handshake, quitar del backlog y añadir a establecidas

  NS_LOG_INFO(" ---> FullConnection address desde from: "<<inetFrom.GetIpv4()<<" port: "<<inetFrom.GetPort());



  NS_LOG_INFO("Pilar fullConnection: tam m_halfOpenSockets antes de borrar "<< m_halfOpenSockets.size()<<" socket "<<socket);
  //m_halfOpenSockets.remove(socket);


  Address peerAddress;
  socket->GetSockName(peerAddress);
  InetSocketAddress pa=InetSocketAddress::ConvertFrom(peerAddress);
  NS_LOG_INFO(" ---> FullConnection address desde socket: "<<pa.GetIpv4()<<" port: "<<pa.GetPort());
  NS_LOG_INFO(" ---> socket: "<<socket);

  //m_halfOpenSockets.remove_if([&](const Ptr<Socket>& s){
  //    Address sadr;
  //    s->GetSockName(sadr);
  //    return sadr==peerAddress; 
  //}); 
 
  m_halfOpenSockets.remove(from);

  NS_LOG_INFO("Pilar fullConnection: tam m_halfOpenSockets despues de borrar "<< m_halfOpenSockets.size()<<" socket "<<socket);
  m_socketList.push_back(socket);
  m_connectionsEstablished++;
  
  NS_LOG_INFO("Connection established from " << inetFrom.GetIpv4() << 
              ". Current Backlog: " << m_halfOpenSockets.size());

  // Configurar callbacks para la conexión establecida
  socket->SetRecvCallback(MakeCallback(&TcpFlowSink::HandleRead, this));
  socket->SetCloseCallbacks(
    MakeCallback(&TcpFlowSink::HandlePeerClose, this),
    MakeCallback(&TcpFlowSink::HandlePeerError, this)
  );
    
  LogConnectionAttempt(true, from, false);
}





// The rest of the handlers remain the same
void TcpFlowSink::HandleRead (Ptr<Socket> socket)
{
 NS_LOG_FUNCTION (this << socket);
 Ptr<Packet> packet;
 Address from;
 while ((packet = socket->RecvFrom (from)))
   {
     if (packet->GetSize () == 0)
       { 
         break;
       }
     m_totalRx += packet->GetSize ();
     //NS_LOG_INFO("--------------> recibido "<<m_totalRx);
   }
}

void TcpFlowSink::HandlePeerClose (Ptr<Socket> socket)
{
 NS_LOG_FUNCTION (this << socket);
 CleanUp (socket);
}

void TcpFlowSink::HandlePeerError (Ptr<Socket> socket)
{
 NS_LOG_FUNCTION (this << socket);
 CleanUp (socket);
}

void TcpFlowSink::CleanUp (Ptr<Socket> socket)
{
 NS_LOG_FUNCTION (this << socket);
 std::list<Ptr<Socket>>::iterator it;
 for (it = m_socketList.begin(); it != m_socketList.end(); ++it)
   {
     if (*it == socket)
       {
         m_socketList.erase(it);
         break;
       }
   }   
}


void
TcpFlowSink::CloseAllSockets (void)
{
  NS_LOG_FUNCTION (this);

  // Close established connections
  while (!m_socketList.empty())
    {
      Ptr<Socket> socket = m_socketList.front();
      m_socketList.pop_front();
      socket->Close();
    }
  
  // Closes half-open connections
  //while (!m_halfOpenSockets.empty())
  //  {
  //    Ptr<Socket> socket = m_halfOpenSockets.front();
  //    m_halfOpenSockets.pop_front();
  //    socket->Close();
  //  }
  
  // Close main socket
  if (m_socket)
    {
      m_socket->Close();
      m_socket = 0;
    }
}

/*
void TcpFlowSink::LogConnectionAttempt(bool established, const Address& from)
{
    std::string logFile = m_baseLogsDir + "/connection_attempts.csv";
    
    //NEW
    // Obtener IP de origen y convertirla a string de forma segura
    InetSocketAddress inetFrom = InetSocketAddress::ConvertFrom(from);
    std::ostringstream sourceIp;
    sourceIp << inetFrom.GetIpv4();  // Esto usará el operador << de Ipv4Address
    
    std::ofstream ofs(logFile, std::ofstream::out | std::ofstream::app);
    ofs << Simulator::Now().GetNanoSeconds() << ","
        << (established ? "ESTABLISHED" : "SYN_RECEIVED") << ","
        << m_synReceived << ","
        << m_connectionsEstablished << ","
        << sourceIp.str()<< std::endl;
    ofs.close();
}*/


void 
TcpFlowSink::LogConnectionAttempt(bool established, const Address& from, bool rejected)
{
  std::string logFile = m_baseLogsDir + "/connection_attempts.csv";
  InetSocketAddress inetFrom = InetSocketAddress::ConvertFrom(from);
    
  std::ofstream ofs(logFile, std::ofstream::out | std::ofstream::app);
  ofs << Simulator::Now().GetNanoSeconds() << ","
      << (established ? "ESTABLISHED" : rejected ? "REJECTED" : "SYN_RECEIVED") << ","
      << m_synReceived << ","
      << m_connectionsEstablished << ","
      << m_halfOpenSockets.size() << ","
      << m_droppedSyns << ","
      << inetFrom.GetIpv4() << std::endl;
  ofs.close();
}


} // namespace ns3
