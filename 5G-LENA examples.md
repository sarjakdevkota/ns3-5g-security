https://cttc-lena.gitlab.io/nr/html/
cttc-nr-demo.cc

flow:-> Host -> Gateway for packet->gNB->UE 
it uses Uu interface between UE and gNB

its working
-number of gNBs and UEs
-2 UEs: one is low-latency traffic receivers and other is voice traffic receivers
UEs are attached to closest gNB using nr helper

nrHelper->AttachToClosestEnb(ueLowLatNetDev, enbNetDev);
nrHelper->AttachToClosestEnb(ueVoiceNetDev, enbNetDev);

a logical connection is created between UE and gNB without any authentication mechanism

uses UDP servers on UE and UDP clients on host

throughput, delay, jitter, and packet loss are measured

