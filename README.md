###############################################################################################################
# Enhancing the Hypatia Simulator for LEO Satellite Networks with Integrated DoS and DDoS Attack Capabilities
###############################################################################################################

Published in: INTERNATIONAL JOURNAL OF INFORMATION SECURITY 

The increasing relevance of Low Earth Orbit (LEO) satellite constellations in next-generation communication sys-
tems highlights the importance of evaluating their security  under realistic threat conditions. Hypatia provides a rich simulation environment for end-to-end LEO communications but lacks native support for modeling cyberattacks. 

This work includes an extension of Hypatia that enables the simulation of Denial of Service (DoS) and Distributed DoS (DDoS) attacks originating from ground stations in the Satellite-Terrestrial Integrated Network (STIN). The framework implements four representative attack types: a state-exhaustion attack (TCP SYN flood), two volumetric attacks (UDP and ICMP floods), and a low-rate pulsing attack (Shrew). 

Attack campaigns are defined through a scheduler file, allowing programmable and reproducible experiments with flexible control of attacker scale and timing. The framework’s effectiveness is demonstrated by analyzing the impact of these attacks on TCP performance across several LEO constellations (Starlink, Kuiper, and Telesat). 

This contribution provides a practical tool for evaluating mitigation strategies and serves as a methodological reference for integrating new attack models, laying the groundwork for future research on security challenges in LEO networks.

--------------------
Enhanced Hypatia developed in this work
--------------------

In order to allow the simulation of tcp-syn attacks, the original tcp-socket-base.cc/.h files in ns-3 simulator must be replaced by the files provided in ns3-sat-sim directory.
The path to the files is:
src/internet/model/tcp-socket-base.cc
src/internet/model/tcp-socket-base.h

Sintaxis in schedule_attack.csv to define the available attacks are:
* Low-rate pulsing (Shrew) attack:
FlowId - FromNodeId - ToNodeId - Attack Duration - Start time - Shrew Attack Params (a string separed by &: burst_period&burst_length&attacker_rate)- shrew

* TCP SYN flood attack:
FlowId - FromNodeId - ToNodeId - Time between packets - Start time - Attack Duration - synflood

* UDP flood attack:
FlowId - FromNodeId - ToNodeId - Time between packets - Start time - Attack Duration - udpflood

* ICMP flood attack:
FlowId - FromNodeId - ToNodeId - Time between packets - Start time - Attack Duration - icmpflood

--------------
Hypatia
--------------

The original Hypatia framework was presented in:

Kassing S, Bhattacherjee D, Águas A, Saethre J, Singla A. Exploring the "Internet from space" with Hypatia. In: Proceedings of the ACM Internet Measurement Conference. 2020:214-229. doi: 10.1145/3419394.3423635

Simulations using Hypatia includes the following steps:

* Step 1 ---> use satgenpy to generate satellite network dynamic state over time
* Step 2 ---> build ns-3 simulator
* Step 3 ---> running ns-3 experiments

