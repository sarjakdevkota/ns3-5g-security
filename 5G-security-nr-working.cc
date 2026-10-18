/* 5G Network Security Implementation in ns3
 * This simulation implements security mechanisms for 5G networks including:
 * - Authentication
 * - Encryption
 * - Intrusion Detection
 * - Attack simulation
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/flow-monitor-module.h"

#include "ns3/nr-module.h"
#include "ns3/epc-helper.h"
 
 using namespace ns3;
 
 NS_LOG_COMPONENT_DEFINE("5GNetworkSecurityExample");
 
 // UE Application
 class UEApplication : public Application {
 public:
   UEApplication() : m_socket(0) {}
   virtual ~UEApplication() {}
   
   static TypeId GetTypeId(void) {
     static TypeId tid = TypeId("UEApplication")
       .SetParent<Application>()
       .SetGroupName("5GNetworkSecurity")
       .AddConstructor<UEApplication>();
     return tid;
   }
 
 protected:
   virtual void StartApplication() {
     m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
     InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 8080);
     m_socket->Bind(local);
     m_socket->SetRecvCallback(MakeCallback(&UEApplication::HandleRead, this));
     Simulator::Schedule(Seconds(2.0), &UEApplication::SendData, this);
   }
 
   virtual void StopApplication() {
     if (m_socket) {
       m_socket->Close();
       m_socket = 0;
     }
   }
 
 private:
   void SendData() {
     uint8_t buffer[8] = "ue-data";
     Ptr<Packet> packet = Create<Packet>(buffer, 7);
     m_socket->SendTo(packet, 0, InetSocketAddress(Ipv4Address("10.1.1.2"), 8080)); // Send to gNB
     Simulator::Schedule(Seconds(5.0), &UEApplication::SendData, this);
   }
 
   void HandleRead(Ptr<Socket> socket) {
     Ptr<Packet> packet;
     Address from;
     while ((packet = socket->RecvFrom(from))) {
       NS_LOG_INFO("UE received: " << packet->GetSize());
     }
   }
 
   Ptr<Socket> m_socket;
 };
 
 // gNB Application
 class gNBApplication : public Application {
 public:
   gNBApplication() : m_socket(0) {}
   virtual ~gNBApplication() {}
   
   static TypeId GetTypeId(void) {
     static TypeId tid = TypeId("gNBApplication")
       .SetParent<Application>()
       .SetGroupName("5GNetworkSecurity")
       .AddConstructor<gNBApplication>();
     return tid;
   }
 
 protected:
   virtual void StartApplication() {
     m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
     InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 8080);
     m_socket->Bind(local);
     m_socket->SetRecvCallback(MakeCallback(&gNBApplication::HandleRead, this));
   }
 
   virtual void StopApplication() {
     if (m_socket) {
       m_socket->Close();
       m_socket = 0;
     }
   }
 
 private:
   void HandleRead(Ptr<Socket> socket) {
     Ptr<Packet> packet;
     Address from;
     while ((packet = socket->RecvFrom(from))) {
       NS_LOG_INFO("gNB received: " << packet->GetSize());
       // Process data and respond if necessary
       std::string responseData = "processed-data";
       uint8_t buffer[15];
       memcpy(buffer, responseData.c_str(), responseData.size());
       Ptr<Packet> responsePacket = Create<Packet>(buffer, responseData.size());
       m_socket->SendTo(responsePacket, 0, InetSocketAddress::ConvertFrom(from));
     }
   }
 
   Ptr<Socket> m_socket;
 };
 
 // Authentication Application
 class AuthApplication : public Application {
 public:
   AuthApplication() : m_socket(0) {}
   virtual ~AuthApplication() {}
   
   static TypeId GetTypeId(void) {
     static TypeId tid = TypeId("AuthApplication")
       .SetParent<Application>()
       .SetGroupName("5GNetworkSecurity")
       .AddConstructor<AuthApplication>();
     return tid;
   }
 
 protected:
   virtual void StartApplication() {
     m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
     InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 7070);
     m_socket->Bind(local);
     m_socket->SetRecvCallback(MakeCallback(&AuthApplication::HandleRead, this));
   }
 
   virtual void StopApplication() {
     if (m_socket) {
       m_socket->Close();
       m_socket = 0;
     }
   }
 
 private:
   void HandleRead(Ptr<Socket> socket) {
     Ptr<Packet> packet;
     Address from;
     while ((packet = socket->RecvFrom(from))) {
       uint8_t buffer[packet->GetSize()];
       packet->CopyData(buffer, packet->GetSize());
       std::string data = std::string((char*)buffer, packet->GetSize());
       
       if (Authenticate(data)) {
         NS_LOG_INFO("Authentication successful from " << InetSocketAddress::ConvertFrom(from).GetIpv4());
         ForwardPacket(packet);
       } else {
         NS_LOG_WARN("Authentication failed from " << InetSocketAddress::ConvertFrom(from).GetIpv4());
       }
     }
   }
 
   bool Authenticate(const std::string& data) {
     // Simplified authentication logic
     return data == "valid-credentials";
   }
 
   void ForwardPacket(Ptr<Packet> packet) {
     Ptr<Socket> socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
     InetSocketAddress remote = InetSocketAddress(Ipv4Address("10.1.1.2"), 8080); // Forward to another node
     socket->Connect(remote);
     socket->Send(packet);
     socket->Close();
   }
 
   Ptr<Socket> m_socket;
 };
 
 // Encryption Application
 class EncryptionApplication : public Application {
 public:
   EncryptionApplication() : m_socket(0) {}
   virtual ~EncryptionApplication() {}
   
   static TypeId GetTypeId(void) {
     static TypeId tid = TypeId("EncryptionApplication")
       .SetParent<Application>()
       .SetGroupName("5GNetworkSecurity")
       .AddConstructor<EncryptionApplication>();
     return tid;
   }
 
 protected:
   virtual void StartApplication() {
     m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
     InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 6060);
     m_socket->Bind(local);
     m_socket->SetRecvCallback(MakeCallback(&EncryptionApplication::HandleRead, this));
   }
 
   virtual void StopApplication() {
     if (m_socket) {
       m_socket->Close();
       m_socket = 0;
     }
   }
 
 private:
   void HandleRead(Ptr<Socket> socket) {
     Ptr<Packet> packet;
     Address from;
     while ((packet = socket->RecvFrom(from))) {
       uint8_t buffer[packet->GetSize()];
       packet->CopyData(buffer, packet->GetSize());
       std::string data = std::string((char*)buffer, packet->GetSize());
       std::string decryptedData = Decrypt(data);
       NS_LOG_INFO("Received encrypted data: " << data << ", decrypted data: " << decryptedData);
     }
   }
 
   std::string Decrypt(const std::string& data) {
     // Simplified decryption logic
     return data; // Assume data is already decrypted for simplicity
   }
 
   Ptr<Socket> m_socket;
 };
 
 // Intrusion Detection System (IDS) Application
 class IDSApplication : public Application {
 public:
   IDSApplication() : m_socket(0) {}
   virtual ~IDSApplication() {}
   
   static TypeId GetTypeId(void) {
     static TypeId tid = TypeId("IDSApplication")
       .SetParent<Application>()
       .SetGroupName("5GNetworkSecurity")
       .AddConstructor<IDSApplication>();
     return tid;
   }
 
 protected:
   virtual void StartApplication() {
     m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
     InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 5050);
     m_socket->Bind(local);
     m_socket->SetRecvCallback(MakeCallback(&IDSApplication::HandleRead, this));
   }
 
   virtual void StopApplication() {
     if (m_socket) {
       m_socket->Close();
       m_socket = 0;
     }
   }
 
 private:
   void HandleRead(Ptr<Socket> socket) {
     Ptr<Packet> packet;
     Address from;
     while ((packet = socket->RecvFrom(from))) {
       uint8_t buffer[packet->GetSize()];
       packet->CopyData(buffer, packet->GetSize());
       std::string data = std::string((char*)buffer, packet->GetSize());
       
       if (DetectIntrusion(data)) {
         NS_LOG_WARN("Intrusion detected from " << InetSocketAddress::ConvertFrom(from).GetIpv4());
       } else {
         NS_LOG_INFO("Normal traffic from " << InetSocketAddress::ConvertFrom(from).GetIpv4());
       }
     }
   }
 
   bool DetectIntrusion(const std::string& data) {
     // Simplified intrusion detection logic
     return data == "malicious-pattern";
   }
 
   Ptr<Socket> m_socket;
 };
 
 // Attacker Application
 class AttackerApplication : public Application {
 public:
   AttackerApplication() : m_socket(0) {}
   virtual ~AttackerApplication() {}
   
   static TypeId GetTypeId(void) {
     static TypeId tid = TypeId("AttackerApplication")
       .SetParent<Application>()
       .SetGroupName("5GNetworkSecurity")
       .AddConstructor<AttackerApplication>();
     return tid;
   }
 
 protected:
   virtual void StartApplication() {
     m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
     m_peer = InetSocketAddress(Ipv4Address("10.1.1.2"), 8080); // Target gNB
     m_socket->Connect(m_peer);
     Simulator::Schedule(Seconds(3.0), &AttackerApplication::SendMaliciousPacket, this);
   }
 
   virtual void StopApplication() {
     if (m_socket) {
       m_socket->Close();
       m_socket = 0;
     }
   }
 
 private:
   void SendMaliciousPacket() {
     std::string maliciousData = "malicious-pattern"; // Simplified malicious pattern
     uint8_t buffer[maliciousData.size() + 1];
     memcpy(buffer, maliciousData.c_str(), maliciousData.size());
     Ptr<Packet> packet = Create<Packet>(buffer, maliciousData.size());
     m_socket->Send(packet);
     NS_LOG_INFO("Attacker sent malicious packet");
   }
 
   Ptr<Socket> m_socket;
   Address m_peer;
 };
 
 int main(int argc, char *argv[]) {
   LogComponentEnable("5GNetworkSecurityExample", LOG_LEVEL_INFO);
   
   CommandLine cmd;
   cmd.Parse(argc, argv);
 
   // Create nodes
   NodeContainer ueNodes;
   ueNodes.Create(2); // User Equipment (UE) nodes
 
   NodeContainer gNbNodes;
   gNbNodes.Create(2); // 5G base stations (gNB) nodes
 
   NodeContainer attackerNode;
   attackerNode.Create(1); // Attacker node
 
   // Set up mobility
   MobilityHelper mobility;
   mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
   mobility.Install(ueNodes);
   mobility.Install(gNbNodes);
   mobility.Install(attackerNode);
 
   // Create the internet
   InternetStackHelper internet;
   internet.Install(ueNodes);
   internet.Install(gNbNodes);
   internet.Install(attackerNode);
 
   // Set up point-to-point connections
   PointToPointHelper pointToPoint;
   pointToPoint.SetDeviceAttribute("DataRate", StringValue("10Gbps"));
   pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));
 
   NetDeviceContainer p2pDevices;
   p2pDevices.Add(pointToPoint.Install(NodeContainer(ueNodes.Get(0), gNbNodes.Get(0))));
   p2pDevices.Add(pointToPoint.Install(NodeContainer(ueNodes.Get(1), gNbNodes.Get(1))));
   p2pDevices.Add(pointToPoint.Install(NodeContainer(gNbNodes.Get(0), gNbNodes.Get(1))));
   p2pDevices.Add(pointToPoint.Install(NodeContainer(gNbNodes.Get(1), attackerNode.Get(0))));
 
   // Install LTE and 5G NR modules
   Ptr<LteHelper> lteHelper = CreateObject<LteHelper>();
   Ptr<mmwave::MmWaveHelper> mmWaveHelper = CreateObject<mmwave::MmWaveHelper>();
   mmWaveHelper->SetEpcHelper(CreateObject<PointToPointEpcHelper>());
   mmWaveHelper->Initialize();
   lteHelper->SetEpcHelper(CreateObject<PointToPointEpcHelper>());
 
   NetDeviceContainer enbDevs = lteHelper->InstallEnbDevice(gNbNodes);
   NetDeviceContainer ueDevs = lteHelper->InstallUeDevice(ueNodes);
 
   // Attach UEs to gNBs
   lteHelper->Attach(ueDevs.Get(0), enbDevs.Get(0));
   lteHelper->Attach(ueDevs.Get(1), enbDevs.Get(1));
 
   // Assign IP addresses
   Ipv4AddressHelper address;
   address.SetBase("10.1.1.0", "255.255.255.0");
   Ipv4InterfaceContainer interfaces = address.Assign(p2pDevices);
 
   // Create and configure UE applications
   for (uint32_t i = 0; i < ueNodes.GetN(); ++i) {
     Ptr<UEApplication> ueApp = CreateObject<UEApplication>();
     ueNodes.Get(i)->AddApplication(ueApp);
     ueApp->SetStartTime(Seconds(1.0));
     ueApp->SetStopTime(Seconds(20.0));
   }
 
   // Create and configure gNB applications
   for (uint32_t i = 0; i < gNbNodes.GetN(); ++i) {
     Ptr<gNBApplication> gNbApp = CreateObject<gNBApplication>();
     gNbNodes.Get(i)->AddApplication(gNbApp);
     gNbApp->SetStartTime(Seconds(1.0));
     gNbApp->SetStopTime(Seconds(20.0));
   }
 
   // Create and configure the Auth application
   Ptr<AuthApplication> authApp = CreateObject<AuthApplication>();
   gNbNodes.Get(1)->AddApplication(authApp);
   authApp->SetStartTime(Seconds(1.0));
   authApp->SetStopTime(Seconds(20.0));
 
   // Create and configure the Encryption application
   Ptr<EncryptionApplication> encryptionApp = CreateObject<EncryptionApplication>();
   gNbNodes.Get(1)->AddApplication(encryptionApp);
   encryptionApp->SetStartTime(Seconds(1.0));
   encryptionApp->SetStopTime(Seconds(20.0));
 
   // Create and configure the IDS application
   Ptr<IDSApplication> idsApp = CreateObject<IDSApplication>();
   gNbNodes.Get(1)->AddApplication(idsApp);
   idsApp->SetStartTime(Seconds(1.0));
   idsApp->SetStopTime(Seconds(20.0));
 
   // Create and configure the Attacker application
   Ptr<AttackerApplication> attackerApp = CreateObject<AttackerApplication>();
   attackerNode.Get(0)->AddApplication(attackerApp);
   attackerApp->SetStartTime(Seconds(3.0));
   attackerApp->SetStopTime(Seconds(4.0));
 
   // Setup Tracing
   AsciiTraceHelper ascii;
   pointToPoint.EnableAsciiAll(ascii.CreateFileStream("5g-security-trace.tr"));
 
   // Configure simulation
   NS_LOG_INFO("Starting 5G Network Security Simulation");
   Simulator::Stop(Seconds(25.0));
   Simulator::Run();
   Simulator::Destroy();
   NS_LOG_INFO("Simulation Completed Successfully");
 
   return 0;
 }
 
