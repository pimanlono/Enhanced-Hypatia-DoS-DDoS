#ifndef TCP_FLOW_SINK_H
#define TCP_FLOW_SINK_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"

//NEW 
#include "ns3/boolean.h"
#include "ns3/string.h"
#include "ns3/traced-value.h"

namespace ns3 {

class Address;
class Socket;
class Packet;

class TcpFlowSink : public Application 
{
public:
  static TypeId GetTypeId (void);
  TcpFlowSink ();
  virtual ~TcpFlowSink ();
//PILAR
  //virtual void StopApplication(void) override;

protected:
  virtual void DoDispose (void);

private:
  // Métodos principales de la aplicación
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void HandleRead (Ptr<Socket> socket);
  void HandlePeerClose (Ptr<Socket> socket);
  void HandlePeerError (Ptr<Socket> socket);
  void CleanUp (Ptr<Socket> socket);
  //Logging
  void LogConnectionAttempt(bool established, const Address& from);  
  //void LogConnectionAttempt(bool established, const Address& from, bool rejected);//NEW 15-12
  void LogConnectionAttempt(bool established, const Address& from, bool rejected);//NEW 15-12

  // Callbacks de manejo de conexión
  bool HandlePreConnectionCallback (Ptr<Socket>, const Address&);
  void HandleFullConnectionCallback (Ptr<Socket>, const Address&);


  
  // Socket principal y listas de sockets
  Ptr<Socket> m_socket;
  Address m_local;
  TypeId m_tid;
  std::list<Ptr<Socket>> m_socketList;       // Conexiones establecidas
  
  //std::list<Ptr<Socket>> m_halfOpenSockets;  // NEW Conexiones half-open
  std::list<Address> m_halfOpenSockets; 

  // Counters
  uint64_t m_totalRx;                    //!< Total bytes received
  uint32_t m_synReceived;                //!< NEW Total SYNs received
  uint32_t m_connectionsEstablished;     //!< NEW Total connections established
  //uint32_t m_maxSynBacklog;             //!< NEW 15-12 Máximo backlog permitido
  //uint32_t m_droppedSyns;               //!< NEW 15-12 SYNs rechazados por backlog lleno
 
  uint32_t m_maxSynBacklog;             //!< NEW 15-12 Máximo backlog permitido
  uint32_t m_droppedSyns;               //!< NEW 15-12 SYNs rechazados por backlog lleno
 
  // Directorio para logs
  std::string m_baseLogsDir;

  
  // NEW Métodos auxiliares
  void CloseAllSockets(void);
 
};

} // namespace ns3

#endif /* TCP_FLOW_SINK_H */
