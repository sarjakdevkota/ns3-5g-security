Network application security- Low-level implementation: Steps to Implement Network Application Security in ns3

ndnSIM integrates OpenSSL for Named Data Networking protocol (Packet signing and verification):ndnSIM: ndnSIM/ndn-cxx/src/security/detail/openssl.hpp File Reference

Vehicle Transportation Security - https://wirelesspt.net/arquivos/docs/mesh/Simulation.of.a.Secure.Ad.Hoc.Network.Routing.Protocol.pdf

Extended an ns‑3 MANET protocol with OpenSSL to simulate “continuous node authentication”. Embedding OpenSSL calls directly into ns-3 C++ applications is straightforward. You can insert post-quantum routines in your V2N client registration code to sign or encrypt initial bootstrapping messages

(PDF) An identity-based authentication scheme for safety messages in WAVE-enabled VANETs Blockchain based and does not implement real PQC. V2N script that measures PQC timing (from OpenSSL/OQS benchmarks) to model certificate-exchange delays.

Other domains - [2309.03338] Exploring Post-Quantum Cryptographic Schemes for TLS in 5G Nb-IoT: Feasibility and Recommendations (2023): Sabancı and Cebe developed a realistic ns‑3 environment to evaluate TLS handshakes for 5G IoT devices using post-quantum cryptography. Their simulation integrates a TLS stack with post-quantum algorithms (Kyber key exchange and Dilithium signatures) to measure latency. NIST’s Kyber algorithm was able to perform key exchange at negligible costs. It was just signatures that caused latency issues. May be able to directly link a PQC-patched OpenSSL into ns-3 and quantify the delay. It’s difficult to find their code, but the paper claims to integrate a PQC TLS stack. Sabanci’s GitHub repo: ns3_allinone/ns-allinone-3.32 at main · ksabanci-marquette/ns3_allinone

https://www2.eecs.berkeley.edu/Pubs/TechRpts/2017/EECS-2017-139.pdf

A Berkeley project on securing smart buildings, researchers integrated ns‑3 with a Node.js-based OpenSSL component to simulate an IoT authentication service. They implemented a local authorization service (“Auth”) that issues and checks credentials for IoT devices, running the actual Auth server and device client code inside Linux Containers (LXC) while ns‑3 simulated the network links. Each container ran the full software stack (Auth in Java, IoT client in Node.js for TLS) and was connected to ns‑3 via tap bridges to simulate WiFi and Ethernet links (TLS handshake). OpenSSL (v1.0.2k in Node.js) to log timing and latency. Basically, ns‑3 served as a network emulator while OpenSSL performed actual certificate verification and secure key exchange. This hybrid approach proved the feasibility of TLS simulations, showing how containerized real-world protocols can be tied into ns‑3 for authenticating IoT clients on WiFi/LTE links. Cannot find code but they seem to use these repos. openssl s_server: oqs-provider/STANDARDS.md at main · open-quantum-safe/oqs-provider For DCE: direct-code-execution/ns-3-dce: Run real programs in the discrete time simulator ns3




https://phdprojects.org/how-to-start-network-encryption-projects-using-ns3/#:~:text=Payload%20Encryption%20and%20Decryption%3A&Execute%20the%20encryption%20and%20decryption,an%20encryption%20library%20like%20OpenSSL.


Here’s a simple example structure to replicate encrypted data transmission to utilize NS3 and an external encryption library (e.g., OpenSSL).

#include “ns3/core-module.h”

#include “ns3/network-module.h”

#include “ns3/internet-module.h”

#include “ns3/point-to-point-module.h”

#include “ns3/applications-module.h”

#include <openssl/aes.h> // Example for external encryption library

using namespace ns3;

class EncryptedApplication : public Application {

public:

EncryptedApplication() {}

virtual ~EncryptedApplication() {}

void Setup(Ptr<Socket> socket, Address address, std::string hiddenMessage, uint32_t packetSize, DataRate dataRate) {

m_socket = socket;

m_peer = address;

m_hiddenMessage = hiddenMessage;

m_packetSize = packetSize;

m_dataRate = dataRate;

m_currentBit = 0;

}

private:

virtual void StartApplication(void) override {

m_socket->Connect(m_peer);

SendPacket();

}

void SendPacket() {

std::string ciphertext = EncryptData(m_hiddenMessage);

Ptr<Packet> packet = Create<Packet>((uint8_t*)ciphertext.c_str(), ciphertext.size());

m_socket->Send(packet);

ScheduleTx();

}

std::string EncryptData(const std::string &data) {

AES_KEY encryptKey;

AES_set_encrypt_key((const unsigned char *)”1234567890123456″, 128, &encryptKey);

unsigned char encrypted[1024];

AES_encrypt((const unsigned char *)data.c_str(), encrypted, &encryptKey);

return std::string((char *)encrypted, data.size());

}

void ScheduleTx() {

Time tNext(Seconds(m_packetSize * 8 / static_cast<double>(m_dataRate.GetBitRate())));

m_sendEvent = Simulator::Schedule(tNext, &EncryptedApplication::SendPacket, this);

}

Ptr<Socket> m_socket;

Address m_peer;

std::string m_hiddenMessage;

uint32_t m_packetSize;

DataRate m_dataRate;

uint32_t m_currentBit;

EventId m_sendEvent;

};

int main(int argc, char *argv[]) {

NodeContainer nodes;

nodes.Create(2);

PointToPointHelper pointToPoint;

pointToPoint.SetDeviceAttribute(“DataRate”, StringValue(“5Mbps”));

pointToPoint.SetChannelAttribute(“Delay”, StringValue(“2ms”));

NetDeviceContainer devices = pointToPoint.Install(nodes);

InternetStackHelper stack;

stack.Install(nodes);

Ipv4AddressHelper address;

address.SetBase(“10.1.1.0”, “255.255.255.0”);

Ipv4InterfaceContainer interfaces = address.Assign(devices);

Ptr<Socket> srcSocket = Socket::CreateSocket(nodes.Get(0), UdpSocketFactory::GetTypeId());

Ptr<Socket> dstSocket = Socket::CreateSocket(nodes.Get(1), UdpSocketFactory::GetTypeId());

Address sinkAddress(InetSocketAddress(interfaces.GetAddress(1), 8080));

Ptr<EncryptedApplication> app = CreateObject<EncryptedApplication>();

app->Setup(srcSocket, sinkAddress, “Confidential Message”, 1024, DataRate(“5Mbps”));

nodes.Get(0)->AddApplication(app);

app->SetStartTime(Seconds(1.0));

app->SetStopTime(Seconds(10.0));

Simulator::Run();

Simulator::Destroy();

return 0;

}