/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#ifndef UDP_ATTACK_HELPER_H
#define UDP_ATTACK_HELPER_H

#include <stdint.h>
#include <string>
#include <cstdlib>// Para stoll
#include "ns3/object-factory.h"
#include "ns3/address.h"
#include "ns3/attribute.h"
#include "ns3/net-device.h"
#include "ns3/node-container.h"
#include "ns3/application-container.h"
#include "ns3/uinteger.h"

//NEW 
#include "ns3/boolean.h"
#include "ns3/string.h"
#include "ns3/ipv4-address.h"

//NEW
namespace ns3 {

class UdpAttackHelper {
public:
    UdpAttackHelper(std::string socketType, 
                   Address address,
                   int64_t flowId,
                   bool enableLogging,
                   std::string baseLogsDir,
                   int64_t synInterval,// synInterval from AdditionalParameters
                   int64_t attackDuration);  //Attack duration in ns

    ApplicationContainer Install(Ptr<Node> node) const;

private:
    Ptr<Application> InstallPriv(Ptr<Node> node) const;
    ObjectFactory m_factory;
};

} // namespace ns3
#endif /* UDP_ATTACK_HELPER_H */
