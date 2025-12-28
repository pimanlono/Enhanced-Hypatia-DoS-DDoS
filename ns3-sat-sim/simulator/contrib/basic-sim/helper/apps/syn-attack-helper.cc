/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "syn-attack-helper.h"
#include "ns3/inet-socket-address.h"
#include "ns3/packet-socket-address.h"
#include "ns3/string.h"
#include "ns3/boolean.h"
#include "ns3/names.h"

//NEW
namespace ns3 {

SynAttackHelper::SynAttackHelper(std::string socketType, 
                               Address address,
                               int64_t flowId,
                               bool enableLogging,
                               std::string baseLogsDir,
                               int64_t synInterval,
                               int64_t attackDuration) //new
                               
{
    m_factory.SetTypeId("ns3::SynAttackApplication");
    m_factory.Set("SocketType", StringValue(socketType));
    m_factory.Set("Remote", AddressValue(address)); //IP and port where endpoint B (DESTINATION) listens
    m_factory.Set("FlowId", UintegerValue(flowId));
    m_factory.Set("EnableLogging", BooleanValue(enableLogging));
    m_factory.Set("BaseLogsDir", StringValue(baseLogsDir));
    // SynInterval in nanoseconds
    m_factory.Set("SynInterval", TimeValue(NanoSeconds(synInterval)));
    // Set EndAttackTime 
    m_factory.Set("AttackDuration", TimeValue(NanoSeconds(attackDuration)));
}

ApplicationContainer
SynAttackHelper::Install(Ptr<Node> node) const
{
    return ApplicationContainer(InstallPriv(node));
}

Ptr<Application>
SynAttackHelper::InstallPriv(Ptr<Node> node) const
{
    Ptr<Application> app = m_factory.Create<Application>();
    node->AddApplication(app);
    return app;
}

} // namespace ns3
