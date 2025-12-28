/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#ifndef SYN_ATTACK_APPLICATION_H
#define SYN_ATTACK_APPLICATION_H



#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/string.h"
#include "ns3/traced-callback.h"

#include "ns3/ipv4-address.h"
#include "ns3/socket.h"
#include "ns3/random-variable-stream.h"
#include "ns3/tcp-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/inet-socket-address.h"
//20-11 NEW
#include "ns3/boolean.h"
#include "ns3/ipv4.h"

//21-11 NEW
#include "ns3/internet-module.h" // Incluye todo el módulo de internet



namespace ns3 {

class Address;
class Socket;

class SynAttackApplication : public Application 
{
public:
  static TypeId GetTypeId (void);
  SynAttackApplication ();
  virtual ~SynAttackApplication ();
  

protected:
  virtual void DoDispose (void);

private:
  virtual void StartApplication (void);
  virtual void StopApplication (void);
  void SendSyn (void);
  void InsertAttackLog (int64_t timestamp, uint32_t syns_sent);

  // Atributos básicos primero
  uint8_t         m_protocol;     //!< Protocol number (6 for TCP) 
  uint16_t        m_dstPort;      //!< Destination port (extracted from m_peer)
  uint16_t	  m_srcPort;
  Ipv4Address     m_srcAddr;     // Dirección origen guardada
  Ipv4Address     m_dstAddr;     //!< Destination address (extracted from m_peer)
  uint32_t        m_count;        //!< Number of SYNs sent
  uint32_t        m_flowId;       //!< Flow identifier
  bool            m_running;      //!< Application state
  
  // Objetos complejos después
  Ptr<Socket>     m_socket;       //!< Raw socket for sending SYNs
  std::string     m_socketType;   //!< Socket type
  Address         m_peer;         //!< Target address
  Time            m_interval;     //!< Interval between SYNs
  EventId         m_sendEvent;    //!< Event for next SYN
  //Time            m_attackStopTime;     //!< Time to stop sending SYNs new
  Time            m_attackDuration;   

  // Attack logging
  bool            m_enableLogging;    //!< Enable logging
  std::string     m_baseLogsDir;      //!< Log directory
  
  // Random number generators
  Ptr<UniformRandomVariable> m_portRng;   //!< For source ports
  Ptr<UniformRandomVariable> m_seqRng;    //!< For sequence numbers
};

} // namespace ns3

#endif /* SYN_ATTACK_APPLICATION_H */
