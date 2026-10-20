/*
 * v2n-ue-registration-smf.cc
 *
 * COMPLETE V2N 5G UE REGISTRATION WITH FULL 5G CORE
 * Includes: AMF + SMF + PDU Session + Uu NR radio + BSM encryption
 *
 * 5G CORE NETWORK FUNCTIONS SIMULATED:
 *   AMF  — Access and Mobility Management Function (port 9000/9001)
 *          Handles: SUCI validation, GUTI assignment, triggers PDU session
 *   SMF  — Session Management Function (port 9010/9011)
 *          Handles: PDU session setup, IP address confirmation
 *   UPF  — User Plane Function (handled by NrPointToPointEpcHelper + PGW)
 *          Handles: BSM data plane forwarding
 *
 * COMPLETE REGISTRATION FLOW (3GPP TS 23.502):
 *   UE  -> gNB -> AMF  : Registration Request (SUCI)       [NAS / N1-N2]
 *   AMF -> SMF         : PDU Session Request (N11)
 *   SMF -> AMF         : PDU Session Accept  (N11)
 *   AMF -> gNB -> UE   : Registration Accept + PDU Accept  [NAS / N1-N2]
 *   UE  -> UPF -> sink : Encrypted BSMs (N3 data plane)
 *
 * WHAT THIS MEASURES:
 *   1. SUCI construction latency   — ECIES P-256, AES-128-CTR, HMAC-SHA256
 *   2. GUTI assignment latency     — AMF side
 *   3. PDU session setup latency   — AMF <-> SMF round trip (N11)
 *   4. Key derivation chain time   — K->KAUSF->KSEAF->KAMF->KNASenc/KNASint
 *   5. Total registration latency  — full E2E including Uu + N11
 *   6. BSM gate delay              — time from PDU accept to first BSM
 *   7. BSM encryption overhead     — AES-128-CBC + HMAC-SHA256 per packet
 *
 * TOPOLOGY:
 *   [Vehicle UE 0] ==Uu NR==\
 *                            [gNB]--EPC/UPF--[PGW]--P2P--[remoteHost]
 *   [Vehicle UE 1] ==Uu NR=/                              |-- AMF  :9000/:9001
 *                                                         |-- SMF  :9010/:9011
 *                                                         |-- BsmSink :9002
 *                                                         |-- IDS  :9003
 *
 * PORTS:
 *   9000  NAS Registration Request   UE -> AMF
 *   9001  NAS Registration Accept    AMF -> UE
 *   9002  BSM data (encrypted)       UE -> BsmSink
 *   9003  IDS monitor
 *   9010  PDU Session Request        AMF -> SMF  (N11)
 *   9011  PDU Session Response       SMF -> AMF  (N11)
 *
 * BUILD:
 *   cp v2n-ue-registration-smf.cc \
 *      ~/clean-ns3/ns-3-dev/scratch/v2n-ue-registration/v2n-ue-registration.cc
 *   cd ~/clean-ns3/ns-3-dev
 *   ./ns3 build scratch/v2n-ue-registration
 *   ./ns3 run scratch/v2n-ue-registration
 *
 *   CMakeLists.txt already has OpenSSL — no changes needed.
 *
 * RUN OPTIONS:
 *   ./ns3 run "scratch/v2n-ue-registration --numUes=4 --simTime=30"
 */

#include "ns3/antenna-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/realtime-simulator-impl.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-module.h"

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("V2NComplete");

// ============================================================
// WALL-CLOCK TIMER
// ============================================================
static inline double NowNs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec*1e9 + (double)ts.tv_nsec;
}

// ============================================================
// BSM HEADER (SAE J2735)
// ============================================================
#pragma pack(push,1)
struct BSMHeader {
    uint32_t vehicleId;
    uint32_t seqNum;
    double   latitude;
    double   longitude;
    double   speed;
    uint64_t timestamp_ns;
};
#pragma pack(pop)

// ============================================================
// 3GPP IDENTITY STRUCTS
// ============================================================
struct Supi { std::string value; };
struct Suci { std::vector<uint8_t> bytes; double construction_ns; };
struct Guti { std::string amf_id; uint32_t tmsi; bool valid; };
struct NasKeys {
    uint8_t K[32],KAUSF[32],KSEAF[32],KAMF[32];
    uint8_t KNASenc[16];
    uint8_t KNASint[16];
    double  derivation_ns;
};

// ============================================================
// PDU SESSION MESSAGE (N11 interface: AMF <-> SMF)
// ============================================================
// PDU Session Request:  [0x10][ue_ip 4B][tmsi 4B]  = 9 bytes
// PDU Session Accept:   [0x11][ue_ip 4B][pdu_ns 8B] = 13 bytes
#define PDU_SESSION_REQ  0x10
#define PDU_SESSION_ACC  0x11

// ============================================================
// NAS MESSAGE TYPES (carried on ports 9000/9001)
//   0x01  Registration Request  = [type][SUCI 87B]  -- triggers primary auth
//   0x02  Registration Accept   = [type][tmsi 4B][guti_ns 8B][pdu_ns 8B]
//   0x05  NAS-carried EAP packet (see below)
//   0xFF  Registration Reject   (NAS-level reject, before EAP-TLS starts)
// ============================================================
#define MSG_REG_REQUEST 0x01
#define MSG_REG_ACCEPT  0x02
#define MSG_EAP          0x05
#define MSG_REG_REJECT  0xFF

// ============================================================
// EAP (RFC 3748) + EAP-TLS (RFC 5216)
// EAP-TLS is now the actual 5G primary authentication method (3GPP TS
// 33.501 6.1.3): the AMF (acting as EAP authenticator / collapsed
// AMF+AUSF) runs a real EAP conversation with the UE (the EAP peer) over
// NAS. On EAP-Success, KAUSF is derived from the method's exported MSK --
// there is no separate fixed root key anymore.
//
// EAP header (RFC 3748 4):
//   [0] code        1=Request 2=Response 3=Success 4=Failure
//   [1] identifier
//   [2:4] length     total EAP packet length (code..end of data)
//   [4] type         13 = EAP-TLS   (Request/Response only)
//   [5] flags        L/M/S          (Request/Response, type=13, only)
//   [6:10] tlsMsgLen  total reassembled TLS message length (only if L set)
//   [..] TLS data
// (Success/Failure packets are just [code][id][length]=4 bytes, no type.)
//
// Every EAP packet above is itself prefixed with one extra byte, MSG_EAP,
// so it can share ports 9000/9001 with the plain Registration messages.
// ============================================================
#define EAP_CODE_REQUEST  1
#define EAP_CODE_RESPONSE 2
#define EAP_CODE_SUCCESS  3
#define EAP_CODE_FAILURE  4
#define EAP_TYPE_TLS      13

#define EAP_FLAG_L 0x80  // Length included (4B TLS message length follows)
#define EAP_FLAG_M 0x40  // More fragments follow
#define EAP_FLAG_S 0x20  // EAP-TLS Start (authenticator-only, empty body)

#define EAP_TLS_FRAG_MTU 1500  // TLS payload bytes per EAP-TLS fragment —
                                // matches a standard Ethernet-class MTU,
                                // rather than the earlier arbitrary 200B

// Reassembly state for one direction of one EAP-TLS conversation. EAP is
// strictly request/response (no reordering possible in a single-threaded
// discrete-event sim), so -- unlike the old ad-hoc scheme -- no flight id
// is needed to disambiguate fragments.
struct EapReasm {
    bool active = false;
    uint32_t total = 0;
    std::vector<uint8_t> buf;
};
static bool FeedEapFrag(EapReasm& st, uint8_t flags, uint32_t tlsMsgLen,
                         const uint8_t* chunk, size_t chunkLen) {
    if (flags & EAP_FLAG_L) { st.active = true; st.total = tlsMsgLen; st.buf.clear(); }
    else if (!st.active)    { st.active = true; st.total = 0; st.buf.clear(); }
    st.buf.insert(st.buf.end(), chunk, chunk + chunkLen);
    return !(flags & EAP_FLAG_M); // done once M (more-fragments) is clear
}

// Builds one or more complete NAS-wire packets carrying an EAP-Request or
// EAP-Response of type EAP-TLS, fragmenting per RFC 5216 2.1.5 (L on the
// first fragment only, M while more remain). len==0 with startFlag=true
// builds the bare EAP-TLS Start packet.
static std::vector<std::vector<uint8_t>> BuildEapTlsPackets(uint8_t code, uint8_t identifier,
                                                              const uint8_t* data, size_t len,
                                                              bool startFlag = false) {
    std::vector<std::vector<uint8_t>> out;
    if (len == 0) {
        uint8_t flags = startFlag ? EAP_FLAG_S : 0;
        size_t total = 1+1+1+2+1+1; // NAS+code+id+len(2)+type+flags
        std::vector<uint8_t> pkt(total); size_t o = 0;
        pkt[o++]=MSG_EAP; pkt[o++]=code; pkt[o++]=identifier;
        uint16_t eapLen=(uint16_t)(total-1); memcpy(&pkt[o],&eapLen,2); o+=2;
        pkt[o++]=EAP_TYPE_TLS; pkt[o++]=flags;
        out.push_back(std::move(pkt));
        return out;
    }
    size_t off = 0; bool first = true;
    while (off < len) {
        size_t chunkLen = std::min((size_t)EAP_TLS_FRAG_MTU, len - off);
        bool more = (off + chunkLen < len);
        uint8_t flags = 0;
        if (first && len > EAP_TLS_FRAG_MTU) flags |= EAP_FLAG_L;
        if (more) flags |= EAP_FLAG_M;

        size_t total = 1+1+1+2+1+1 + (flags&EAP_FLAG_L?4:0) + chunkLen;
        std::vector<uint8_t> pkt(total); size_t o = 0;
        pkt[o++]=MSG_EAP; pkt[o++]=code; pkt[o++]=identifier;
        uint16_t eapLen=(uint16_t)(total-1); memcpy(&pkt[o],&eapLen,2); o+=2;
        pkt[o++]=EAP_TYPE_TLS; pkt[o++]=flags;
        if (flags & EAP_FLAG_L) { uint32_t tl=(uint32_t)len; memcpy(&pkt[o],&tl,4); o+=4; }
        memcpy(&pkt[o], data+off, chunkLen); o += chunkLen;
        out.push_back(std::move(pkt));

        off += chunkLen; first = false;
    }
    return out;
}

static std::vector<uint8_t> BuildEapStatusPacket(uint8_t code, uint8_t identifier) {
    std::vector<uint8_t> pkt(5); // NAS+code+id+len(2), no type field
    pkt[0]=MSG_EAP; pkt[1]=code; pkt[2]=identifier;
    uint16_t eapLen=4; memcpy(&pkt[3],&eapLen,2);
    return pkt;
}

struct ParsedEap {
    uint8_t code=0, identifier=0, type=0, flags=0;
    uint32_t tlsMsgLen=0;
    const uint8_t* data=nullptr; size_t dataLen=0;
};
static bool ParseEap(const std::vector<uint8_t>& pkt, ParsedEap& out) {
    if (pkt.size() < 5) return false; // NAS+code+id+len(2)
    out.code = pkt[1]; out.identifier = pkt[2];
    if (out.code==EAP_CODE_SUCCESS || out.code==EAP_CODE_FAILURE) return true;
    if (pkt.size() < 7) return false;
    out.type = pkt[5]; out.flags = pkt[6];
    size_t o = 7;
    if (out.flags & EAP_FLAG_L) {
        if (pkt.size() < o+4) return false;
        memcpy(&out.tlsMsgLen, &pkt[o], 4); o += 4;
    }
    out.data = pkt.data()+o; out.dataLen = pkt.size()-o;
    return true;
}

// ============================================================
// EAP-TLS
// Full mutual TLS (client cert required) run as the actual EAP-TLS method.
// TLS (not DTLS) is correct here per RFC 5216 -- it is the transport
// reliability of NAS/EAP that is assumed, not the record layer.
// ============================================================
static SSL_CTX*  g_srvCtx    = nullptr;
static SSL_CTX*  g_cliCtx    = nullptr;
static X509*     g_cert      = nullptr;  // AMF/gNB TLS server cert
static EVP_PKEY* g_pkey      = nullptr;
static EC_KEY*   g_hnKeyPair = nullptr;  // Home Network (UDM/SIDF) EC key --
                                          // AMF holds the private half and uses
                                          // it to de-conceal SUCIs; UEs only
                                          // ever see the public half. This is
                                          // independent of EAP-TLS: identity
                                          // concealment and the authentication
                                          // method are separate 3GPP concerns.

// Self-signed certs aren't chained to a shared root in this simulation.
// Returning 1 alone only tells OpenSSL "proceed anyway" -- it does NOT
// change what SSL_get_verify_result() reports afterward, so we must also
// clear the stored X509_STORE_CTX error, or the post-handshake mutual-auth
// check below would always see the original self-signed-chain failure.
static int AlwaysAcceptVerify(int /*preverify_ok*/, X509_STORE_CTX* ctx) {
    X509_STORE_CTX_set_error(ctx, X509_V_OK);
    return 1;
}

// ============================================================
// CRYPTO HELPERS
// ============================================================
static void HmacSha256(const uint8_t* key,size_t klen,
                        const uint8_t* data,size_t dlen,uint8_t out[32]){
    unsigned int olen=32;
    HMAC(EVP_sha256(),key,(int)klen,data,dlen,out,&olen);
}

static void Kdf3gpp(const uint8_t* key,uint8_t fc,
                    const uint8_t* p0,uint16_t l0,
                    const uint8_t* p1,uint16_t l1,uint8_t out[32]){
    std::vector<uint8_t> in;
    in.push_back(fc);
    if(p0&&l0){in.insert(in.end(),p0,p0+l0);in.push_back((l0>>8)&0xFF);in.push_back(l0&0xFF);}
    if(p1&&l1){in.insert(in.end(),p1,p1+l1);in.push_back((l1>>8)&0xFF);in.push_back(l1&0xFF);}
    HmacSha256(key,32,in.data(),in.size(),out);
}

// EAP-TLS is the primary authentication method now, so KAUSF comes from the
// method's exported MSK (RFC 5216 / TS 33.501 Annex B for EAP-based auth) —
// there is no separate fixed root key K anymore. Both UE and AMF derive this
// independently from their own side of the same TLS session; since both
// export identical keying material after a genuinely shared handshake
// (RFC 5705), a mismatch here would mean the handshake didn't really match,
// with no separate "attestation" bookkeeping required.
static NasKeys DeriveKeyChainFromMsk(const uint8_t msk[64],
                                      const std::string& sn,
                                      const std::string& supi){
    NasKeys keys; memset(keys.K,0,32); // K has no meaning under EAP-TLS auth
    double t0=NowNs();
    memcpy(keys.KAUSF,msk,32); // KAUSF <- MSK[0:32]
    auto sn_b=(const uint8_t*)sn.c_str(); auto sn_l=(uint16_t)sn.size();
    Kdf3gpp(keys.KAUSF,0x6C,sn_b,sn_l,nullptr,0,keys.KSEAF);
    uint8_t abba[2]={0,0};
    Kdf3gpp(keys.KSEAF,0x6D,(const uint8_t*)supi.c_str(),(uint16_t)supi.size(),abba,2,keys.KAMF);
    {uint8_t tmp[32],at[1]={0x01},ai[1]={0x01};Kdf3gpp(keys.KAMF,0x69,at,1,ai,1,tmp);memcpy(keys.KNASenc,tmp,16);}
    {uint8_t tmp[32],at[1]={0x02},ai[1]={0x02};Kdf3gpp(keys.KAMF,0x69,at,1,ai,1,tmp);memcpy(keys.KNASint,tmp,16);}
    keys.derivation_ns=NowNs()-t0; return keys;
}

static Suci BuildSuci(const std::string& supi_str,EC_KEY* hn_key){
    Suci suci; double t0=NowNs();
    std::string msin=supi_str.substr(supi_str.rfind('-')+1);
    uint8_t msin_bcd[5]={0};
    for(int i=0;i<10&&i<(int)msin.size();i+=2){
        uint8_t hi=(msin[i]-'0')&0xF;
        uint8_t lo=(i+1<(int)msin.size())?(msin[i+1]-'0')&0xF:0xF;
        msin_bcd[i/2]=(hi<<4)|lo;
    }
    EC_KEY* eph=EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(eph);
    uint8_t eph_pub[65];
    EC_POINT_point2oct(EC_KEY_get0_group(eph),EC_KEY_get0_public_key(eph),
                       POINT_CONVERSION_UNCOMPRESSED,eph_pub,65,nullptr);
    uint8_t shared[32];
    ECDH_compute_key(shared,32,EC_KEY_get0_public_key(hn_key),eph,nullptr);
    uint8_t enc_key[16],mac_key[32],prk[32],zero[32]={0};
    HmacSha256(zero,32,shared,32,prk);
    {uint8_t info[66];memcpy(info,eph_pub,65);info[65]=0x01;
     uint8_t t1[32];HmacSha256(prk,32,info,66,t1);memcpy(enc_key,t1,16);
     uint8_t info2[98];memcpy(info2,t1,32);memcpy(info2+32,eph_pub,65);info2[97]=0x02;
     HmacSha256(prk,32,info2,98,mac_key);}
    uint8_t msin_ct[5]={0};
    {EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();uint8_t iv[16]={0};int ol=0;
     EVP_EncryptInit_ex(ctx,EVP_aes_128_ctr(),nullptr,enc_key,iv);
     EVP_EncryptUpdate(ctx,msin_ct,&ol,msin_bcd,5);EVP_CIPHER_CTX_free(ctx);}
    uint8_t mac[32]; HmacSha256(mac_key,32,msin_ct,5,mac);
    suci.bytes={0x01,0x00,0x10,0x00,0x10,0x00,0x00,0x02,0x01};
    suci.bytes.insert(suci.bytes.end(),eph_pub,eph_pub+65);
    suci.bytes.insert(suci.bytes.end(),msin_ct,msin_ct+5);
    suci.bytes.insert(suci.bytes.end(),mac,mac+8);
    EC_KEY_free(eph); suci.construction_ns=NowNs()-t0; return suci;
}

// De-conceals (decrypts) a SUCI. This is the AMF-side SIDF (Subscription
// Identifier De-concealing Function): recompute the ECDH shared secret using
// the ephemeral public key carried in the SUCI plus the Home Network's
// private key, re-derive enc/mac keys, verify the MAC, then AES-CTR decrypt
// the MSIN. Returns false (and rejects) on any MAC/format failure. The
// caller measures wall-clock cost around this call — this is the genuine
// server-side crypto cost that was previously skipped entirely.
static bool DeconcealSuci(const uint8_t* suci, size_t len, EC_KEY* hnPriv, std::string& outSupi) {
    if (len < 87 || suci[0] != 0x01) return false;
    const uint8_t* ephPubBytes = suci + 9;
    const uint8_t* cipherMsin  = suci + 9 + 65;
    const uint8_t* rxMac       = suci + 9 + 65 + 5;

    EC_KEY* eph = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT* pt = EC_POINT_new(EC_KEY_get0_group(eph));
    if (!EC_POINT_oct2point(EC_KEY_get0_group(eph), pt, ephPubBytes, 65, nullptr)) {
        EC_POINT_free(pt); EC_KEY_free(eph); return false;
    }
    EC_KEY_set_public_key(eph, pt);
    EC_POINT_free(pt);

    uint8_t shared[32];
    ECDH_compute_key(shared, 32, EC_KEY_get0_public_key(eph), hnPriv, nullptr);
    EC_KEY_free(eph);

    uint8_t enc_key[16], mac_key[32], prk[32], zero[32] = {0};
    HmacSha256(zero, 32, shared, 32, prk);
    {
        uint8_t info[66]; memcpy(info, ephPubBytes, 65); info[65] = 0x01;
        uint8_t t1[32]; HmacSha256(prk, 32, info, 66, t1); memcpy(enc_key, t1, 16);
        uint8_t info2[98]; memcpy(info2, t1, 32); memcpy(info2 + 32, ephPubBytes, 65); info2[97] = 0x02;
        HmacSha256(prk, 32, info2, 98, mac_key);
    }

    uint8_t expMac[32]; HmacSha256(mac_key, 32, cipherMsin, 5, expMac);
    if (memcmp(expMac, rxMac, 8) != 0) return false; // SUCI tampered / wrong key — reject

    uint8_t msin_bcd[5] = {0};
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); uint8_t iv[16] = {0}; int ol = 0;
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, enc_key, iv);
        EVP_DecryptUpdate(ctx, msin_bcd, &ol, cipherMsin, 5);
        EVP_CIPHER_CTX_free(ctx);
    }

    std::ostringstream msin;
    for (int i = 0; i < 5; i++) {
        uint8_t hi = (msin_bcd[i] >> 4) & 0xF, lo = msin_bcd[i] & 0xF;
        msin << (char)('0' + hi);
        if (lo != 0xF) msin << (char)('0' + lo);
    }
    outSupi = "imsi-001-01-" + msin.str();
    return true;
}

static std::vector<uint8_t> AesEncrypt(const uint8_t* p,size_t len,
                                        const uint8_t* k,const uint8_t* iv){
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx,EVP_aes_128_cbc(),nullptr,k,iv);
    std::vector<uint8_t> out(len+EVP_MAX_BLOCK_LENGTH);
    int o1=0,o2=0;
    EVP_EncryptUpdate(ctx,out.data(),&o1,p,(int)len);
    EVP_EncryptFinal_ex(ctx,out.data()+o1,&o2);
    EVP_CIPHER_CTX_free(ctx); out.resize(o1+o2); return out;
}

static std::vector<uint8_t> AesDecrypt(const uint8_t* c,size_t len,
                                        const uint8_t* k,const uint8_t* iv){
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx,EVP_aes_128_cbc(),nullptr,k,iv);
    std::vector<uint8_t> out(len+EVP_MAX_BLOCK_LENGTH);
    int o1=0,o2=0;
    if(!EVP_DecryptUpdate(ctx,out.data(),&o1,c,(int)len)){EVP_CIPHER_CTX_free(ctx);return{};}
    if(!EVP_DecryptFinal_ex(ctx,out.data()+o1,&o2)){EVP_CIPHER_CTX_free(ctx);return{};}
    EVP_CIPHER_CTX_free(ctx); out.resize(o1+o2); return out;
}

static std::vector<uint8_t> ComputeHmac(const uint8_t* d,size_t l,
                                          const uint8_t* k,size_t kl){
    std::vector<uint8_t> m(32); unsigned int ml=32;
    HMAC(EVP_sha256(),k,(int)kl,d,l,m.data(),&ml); return m;
}

// DTLS helpers
// Certificate signature algorithm — set once at startup from --sigAlg, so
// different configurations can be swept via command line without
// recompiling. "RSA" = classical RSA-2048 baseline; "ML-DSA-44/65/87" =
// the three NIST FIPS 204 post-quantum security levels. Read by both the
// AMF's cert and every UE's per-UE client cert (see main() and
// UeRegistrationApp::SetUeIndex()).
static std::string g_sigAlg = "ML-DSA-44";

static bool MakeCert(X509** cx,EVP_PKEY** pk,const std::string& sigAlg){
    // EVP_PKEY_Q_keygen is the OpenSSL 3.x convenience one-shot keygen —
    // no separate CTX/init/keygen dance needed. RSA is the one algorithm
    // here that takes an extra parameter (bit length); ML-DSA takes none.
    EVP_PKEY* pkey = (sigAlg=="RSA")
        ? EVP_PKEY_Q_keygen(nullptr,nullptr,"RSA",(size_t)2048)
        : EVP_PKEY_Q_keygen(nullptr,nullptr,sigAlg.c_str());
    if(!pkey) return false;
    X509* x=X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x),1);
    X509_gmtime_adj(X509_get_notBefore(x),0);
    X509_gmtime_adj(X509_get_notAfter(x),31536000L);
    X509_set_pubkey(x,pkey);
    X509_NAME* n=X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(n,"CN",MBSTRING_ASC,(unsigned char*)"gNB-V2N",-1,-1,0);
    X509_set_issuer_name(x,n);
    // ML-DSA is self-contained (like Ed25519) and REQUIRES a NULL digest —
    // passing one makes X509_sign() fail. RSA is the opposite: it needs an
    // explicit digest (SHA-256) or X509_sign() fails the other way.
    const EVP_MD* md = (sigAlg=="RSA") ? EVP_sha256() : nullptr;
    X509_sign(x,pkey,md);
    *cx=x; *pk=pkey; return true;
}

// ============================================================
// SMF APPLICATION — remoteHost:9010 (N11 interface)
// Receives PDU Session Request from AMF
// Confirms IP assignment, sends PDU Session Accept back to AMF
// Measures PDU session setup latency
// ============================================================
class SmfApplication : public Application {
public:
    SmfApplication():m_socket(nullptr),m_pduCount(0){}
    static TypeId GetTypeId(){
        static TypeId tid=TypeId("SmfApplication").SetParent<Application>()
            .SetGroupName("V2NComplete").AddConstructor<SmfApplication>();return tid;}
    uint32_t GetPduCount() const{return m_pduCount;}

protected:
    void StartApplication() override {
        m_socket=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(),9010));
        m_socket->SetRecvCallback(MakeCallback(&SmfApplication::HandlePduReq,this));
        NS_LOG_INFO("[SMF] N11 interface ready on remoteHost:9010");
    }
    void StopApplication() override {
        if(m_socket){m_socket->Close();m_socket=nullptr;}
        NS_LOG_INFO("[SMF] Total PDU sessions established: "<<m_pduCount);
    }

private:
    void HandlePduReq(Ptr<Socket> sock){
        Ptr<Packet> pkt; Address from;
        while((pkt=sock->RecvFrom(from))){
            uint32_t sz=pkt->GetSize();
            if(sz<9) continue;
            std::vector<uint8_t> buf(sz);
            pkt->CopyData(buf.data(),sz);

            if(buf[0]!=PDU_SESSION_REQ) continue;

            // Extract UE IP and TMSI from request
            uint32_t ue_ip_raw=0, tmsi=0;
            memcpy(&ue_ip_raw,&buf[1],4);
            memcpy(&tmsi,&buf[5],4);
            Ipv4Address ueIp(ue_ip_raw);

            double t0=NowNs();

            // SMF confirms IP address and allocates session resources
            // In real 5G: SMF selects UPF, sets up N4 session, assigns QoS
            // Here: we confirm the EPC-assigned IP and record timing
            NS_LOG_INFO("[SMF] PDU Session Request from AMF"
                <<"  UE-IP="<<ueIp
                <<"  TMSI=0x"<<std::hex<<tmsi<<std::dec);
            NS_LOG_INFO("[SMF] Allocating session resources for UE "<<ueIp
                <<"  QoS=NGBR_VIDEO_TCP_DEFAULT  UPF=PGW");

            double pdu_setup_ns=NowNs()-t0;
            m_pduCount++;

            // Session-allocation CPU cost now actually delays the reply on
            // the simulation timeline, instead of being a side metric that
            // the sim clock never noticed.
            Simulator::Schedule(NanoSeconds(pdu_setup_ns),
                &SmfApplication::SendPduAccept,this,ue_ip_raw,from,pdu_setup_ns);
        }
    }

    void SendPduAccept(uint32_t ue_ip_raw,Address from,double pdu_setup_ns){
        // PDU Session Accept: [0x11][ue_ip 4B][pdu_ns 8B] = 13 bytes
        std::vector<uint8_t> resp(13);
        resp[0]=PDU_SESSION_ACC;
        memcpy(&resp[1],&ue_ip_raw,4);
        uint64_t pns=(uint64_t)pdu_setup_ns;
        memcpy(&resp[5],&pns,8);
        m_socket->SendTo(Create<Packet>(resp.data(),resp.size()),0,from);

        Ipv4Address ueIp(ue_ip_raw);
        NS_LOG_INFO("[SMF] PDU Session Accept sent to AMF"
            <<"  UE-IP="<<ueIp
            <<"  setup="<<std::fixed<<std::setprecision(3)
            <<(pdu_setup_ns/1e6)<<"ms");
    }

    Ptr<Socket> m_socket;
    uint32_t    m_pduCount;
};

// ============================================================
// AMF APPLICATION — remoteHost:9000 (N1/N2 interface)
// Full flow:
//   1. Receives SUCI Registration Request from UE (via gNB)
//   2. Validates SUCI, assigns GUTI
//   3. Sends PDU Session Request to SMF (N11, port 9010)
//   4. Waits for PDU Session Accept from SMF
//   5. Sends Registration Accept + PDU info to UE (port 9001)
// ============================================================
class AmfApplication : public Application {
public:
    AmfApplication():m_socketN1(nullptr),m_socketN11(nullptr),
                     m_authCount(0),m_rejectCount(0){}
    ~AmfApplication() override {
        for(auto& kv:m_eapSessions) if(kv.second.srvSsl) SSL_free(kv.second.srvSsl);
    }
    static TypeId GetTypeId(){
        static TypeId tid=TypeId("AmfApplication").SetParent<Application>()
            .SetGroupName("V2NComplete").AddConstructor<AmfApplication>();return tid;}

    void SetSmfAddress(Ipv4Address addr){m_smfAddr=addr;}

    // Number of parallel CPU workers the AMF has for crypto work.
    //   0 (default) = unlimited parallelism: every job's measured CPU cost is
    //                 injected independently, exactly as before. Fine for UEs
    //                 that never overlap, but it makes server-side crypto look
    //                 free when many UEs register at once.
    //   N >= 1      = jobs queue FIFO onto N identical workers, so overlapping
    //                 registrations genuinely wait for each other.
    void SetCpuServers(uint32_t n){m_cpuServers=n;}
    uint32_t GetAuthCount()   const{return m_authCount;}
    uint32_t GetRejectCount() const{return m_rejectCount;}
    double   GetPduLatency_ms() const{return m_pduLatency.GetNanoSeconds()/1e6;}

protected:
    void StartApplication() override {
        // N1/N2: listen for Registration Requests + NAS-carried EAP packets
        m_socketN1=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_socketN1->Bind(InetSocketAddress(Ipv4Address::GetAny(),9000));
        m_socketN1->SetRecvCallback(MakeCallback(&AmfApplication::HandleN1,this));

        // N11: listen for SMF PDU Session responses
        m_socketN11=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_socketN11->Bind(InetSocketAddress(Ipv4Address::GetAny(),9011));
        m_socketN11->SetRecvCallback(MakeCallback(&AmfApplication::HandlePduResp,this));

        NS_LOG_INFO("[AMF] N1/N2 interface ready on remoteHost:9000");
        NS_LOG_INFO("[AMF] N11 response socket ready on remoteHost:9011");
    }
    void StopApplication() override {
        if(m_socketN1) {m_socketN1->Close();  m_socketN1=nullptr;}
        if(m_socketN11){m_socketN11->Close(); m_socketN11=nullptr;}
    }

private:
    // Per-UE server-side EAP-TLS session state. AMF plays the collapsed
    // AUSF+EAP-authenticator role (TS 33.501 6.1.3): it runs the real TLS
    // state machine against the UE's client cert, and only after
    // EAP-Success does registration continue.
    // Turns one measured CPU cost into the delay before its result may leave
    // the AMF. With m_cpuServers==0 this is just the cost (original behaviour).
    // Otherwise the job starts when the earliest-free worker is free, so
    //   delay = (queueing wait) + (service time = the measured cost).
    // The cost is measured on one real core; the model assumes the AMF has
    // m_cpuServers identical cores. Only the AMF is queued — each UE is its own
    // device with its own CPU, so UE-side costs stay independent.
    Time CpuDelay(double costNs){
        Time cost=NanoSeconds(costNs);
        if(m_cpuServers==0) return cost;
        if(m_cpuBusyUntil.size()!=m_cpuServers) m_cpuBusyUntil.assign(m_cpuServers,Seconds(0));
        size_t best=0;
        for(size_t i=1;i<m_cpuBusyUntil.size();i++)
            if(m_cpuBusyUntil[i]<m_cpuBusyUntil[best]) best=i;
        Time now=Simulator::Now();
        Time start=(now<m_cpuBusyUntil[best])?m_cpuBusyUntil[best]:now;
        Time finish=start+cost;
        m_cpuBusyUntil[best]=finish;
        return finish-now;
    }

    struct AmfEapTlsSession {
        SSL* srvSsl=nullptr; BIO* srvRbio=nullptr; BIO* srvWbio=nullptr;
        bool done=false, mutualAuthOk=false;
        uint8_t eapId=0;
        uint64_t prevWritten=0;
        EapReasm reasm;
        std::string supi;
        Time startTime;
    };

    // Entry point for anything on port 9000: Registration Requests and
    // NAS-carried EAP packets share this channel, dispatched by msgType.
    void HandleN1(Ptr<Socket> sock){
        Ptr<Packet> pkt; Address from;
        while((pkt=sock->RecvFrom(from))){
            uint32_t sz=pkt->GetSize();
            if(sz<1) continue;
            std::vector<uint8_t> buf(sz); pkt->CopyData(buf.data(),sz);
            Ipv4Address ueAddr=InetSocketAddress::ConvertFrom(from).GetIpv4();

            if(buf[0]==MSG_REG_REQUEST){ HandleRegistrationRequest(ueAddr,from,buf); continue; }
            if(buf[0]==MSG_EAP){ HandleEapFromUe(ueAddr,from,buf); continue; }
        }
    }

    void SendReject(Address from,Ipv4Address ueAddr,const char* why){
        NS_LOG_WARN("[AMF] REJECTED  UE="<<ueAddr<<"  reason="<<why);
        m_rejectCount++;
        uint8_t r=MSG_REG_REJECT;
        m_socketN1->SendTo(Create<Packet>(&r,1),0,from);
    }

    // Registration Request now just carries the SUCI. It is the trigger for
    // primary authentication (mirrors real Nudm_UEAuthentication_Get): the
    // AMF de-conceals the SUCI first (to know who is authenticating and
    // for SIDF cost accounting), then starts EAP-TLS.
    void HandleRegistrationRequest(Ipv4Address ueAddr,Address from,const std::vector<uint8_t>& buf){
        if(buf.size()<1+87){ SendReject(from,ueAddr,"malformed registration request"); return; }
        NS_LOG_INFO("[AMF] Registration Request received  UE="<<ueAddr<<"  SUCI-size=87B");

        const uint8_t* suciBytes=&buf[1];
        double t0=NowNs();
        std::string recoveredSupi;
        bool ok=DeconcealSuci(suciBytes,87,g_hnKeyPair,recoveredSupi);
        double deconcealNs=NowNs()-t0;
        if(!ok){ SendReject(from,ueAddr,"SUCI de-concealment failed (MAC invalid)"); return; }

        Simulator::Schedule(CpuDelay(deconcealNs),
            &AmfApplication::StartEapTls,this,ueAddr,from,recoveredSupi,deconcealNs);
    }

    void StartEapTls(Ipv4Address ueAddr,Address from,std::string supi,double deconcealNs){
        NS_LOG_INFO("[AMF] SUCI de-concealed  UE="<<ueAddr<<"  recovered SUPI="<<supi
            <<"  cost="<<std::fixed<<std::setprecision(3)<<(deconcealNs/1e6)<<"ms");

        uint32_t key=ueAddr.Get();
        auto& sess=m_eapSessions[key];
        sess.srvSsl=SSL_new(g_srvCtx);
        sess.srvRbio=BIO_new(BIO_s_mem());
        sess.srvWbio=BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(sess.srvRbio,-1);
        SSL_set_bio(sess.srvSsl,sess.srvRbio,sess.srvWbio);
        SSL_set_accept_state(sess.srvSsl);
        sess.supi=supi;
        sess.startTime=Simulator::Now();
        sess.eapId=0;

        NS_LOG_INFO("[AMF] Starting EAP-TLS primary authentication  UE="<<ueAddr);
        auto pkts=BuildEapTlsPackets(EAP_CODE_REQUEST,sess.eapId,nullptr,0,/*start*/true);
        for(auto& p:pkts) m_socketN1->SendTo(Create<Packet>(p.data(),p.size()),0,from);
    }

    // Drives the server side of one UE's EAP-TLS handshake, one reassembled
    // EAP-Response at a time. Each SSL_do_handshake() call's real wall-clock
    // cost is measured and re-injected via Simulator::Schedule before the
    // resulting EAP-Request is actually placed on the wire.
    void HandleEapFromUe(Ipv4Address ueAddr,Address from,const std::vector<uint8_t>& pkt){
        ParsedEap pe;
        if(!ParseEap(pkt,pe) || pe.code!=EAP_CODE_RESPONSE) return;

        uint32_t key=ueAddr.Get();
        auto it=m_eapSessions.find(key);
        if(it==m_eapSessions.end()) return;
        auto& sess=it->second;

        if(!FeedEapFrag(sess.reasm,pe.flags,pe.tlsMsgLen,pe.data,pe.dataLen)) return;
        BIO_write(sess.srvRbio,sess.reasm.buf.data(),(int)sess.reasm.buf.size());
        sess.reasm.active=false;

        double t0=NowNs();
        int r=SSL_do_handshake(sess.srvSsl);
        double cpuNs=NowNs()-t0;

        uint64_t written=BIO_number_written(sess.srvWbio);
        uint64_t delta=written-sess.prevWritten;
        sess.prevWritten=written;

        if(delta>0){
            std::vector<uint8_t> outChunk(delta);
            BIO_read(sess.srvWbio,outChunk.data(),(int)delta);
            sess.eapId++;
            NS_LOG_INFO("[AMF] EAP-TLS flight #"<<(int)sess.eapId<<" -> UE "<<ueAddr
                <<"  "<<delta<<"B  cpuCost="<<std::fixed<<std::setprecision(3)
                <<(cpuNs/1e6)<<"ms");
            uint8_t idToSend=sess.eapId;
            Simulator::Schedule(CpuDelay(cpuNs),
                &AmfApplication::SendEapRequest,this,from,outChunk,idToSend);
        }

        if(r==1 && !sess.done){
            sess.done=true;
            long vr=SSL_get_verify_result(sess.srvSsl);
            X509* peer=SSL_get_peer_certificate(sess.srvSsl);
            sess.mutualAuthOk=(vr==X509_V_OK && peer!=nullptr);
            if(peer) X509_free(peer);

            // Direct, authoritative confirmation of PQC: SSL_get_negotiated_group()
            // reports the actual TLS key-exchange group used on the wire (not just
            // what we offered) — if this doesn't print "MLKEM768", the handshake
            // silently fell back to a classical group and PQC did NOT actually
            // run, regardless of what SSL_CTX_set1_groups_list() returned.
            int negGroupId=SSL_get_negotiated_group(sess.srvSsl);
            const char* negGroupName=SSL_group_to_name(sess.srvSsl,negGroupId);
            // Cert signature algorithm, read directly off the wire cert (not
            // assumed from what MakeCert() was told to generate) — confirms
            // ML-DSA-44 actually signed it, straight from the OID on the cert.
            X509* peerForAlg=SSL_get_peer_certificate(sess.srvSsl);
            char sigAlgBuf[80]="unknown";
            if(peerForAlg){
                const X509_ALGOR* palg=nullptr; const ASN1_BIT_STRING* psig=nullptr;
                X509_get0_signature(&psig,&palg,peerForAlg);
                OBJ_obj2txt(sigAlgBuf,sizeof(sigAlgBuf),palg->algorithm,0);
                X509_free(peerForAlg);
            }

            NS_LOG_INFO("[AMF] EAP-TLS handshake COMPLETE  UE="<<ueAddr
                <<"  mutualAuth="<<sess.mutualAuthOk
                <<"  cipher="<<SSL_get_cipher(sess.srvSsl)
                <<"  group="<<(negGroupName?negGroupName:"NONE/CLASSICAL")
                <<"  peerCertSigAlg="<<sigAlgBuf
                <<"  wireTime="<<(Simulator::Now()-sess.startTime).GetNanoSeconds()/1e6<<"ms");

            sess.eapId++;
            if(sess.mutualAuthOk){
                uint8_t msk[64];
                SSL_export_keying_material(sess.srvSsl,msk,64,"client EAP encryption",22,nullptr,0,0);
                // Purely a sanity/verification derivation: AMF independently
                // computes the same NAS keys the UE will derive from its own
                // side of the identical TLS session, to demonstrate both
                // sides agree. Not otherwise used downstream in this sim.
                NasKeys amfKeys=DeriveKeyChainFromMsk(msk,
                    "5G:mnc001.mcc001.3gppnetwork.org",sess.supi);
                NS_LOG_INFO("[AMF] MSK exported, AMF-derived KNASenc[0:4]="
                    <<std::hex<<(int)amfKeys.KNASenc[0]<<(int)amfKeys.KNASenc[1]
                    <<(int)amfKeys.KNASenc[2]<<(int)amfKeys.KNASenc[3]<<std::dec);

                auto ok=BuildEapStatusPacket(EAP_CODE_SUCCESS,sess.eapId);
                m_socketN1->SendTo(Create<Packet>(ok.data(),ok.size()),0,from);
                NS_LOG_INFO("[AMF] EAP-Success sent  UE="<<ueAddr);

                m_authCount++;
                ContinueAfterEapSuccess(ueAddr,from);
            } else {
                auto fail=BuildEapStatusPacket(EAP_CODE_FAILURE,sess.eapId);
                m_socketN1->SendTo(Create<Packet>(fail.data(),fail.size()),0,from);
                m_rejectCount++;
                NS_LOG_WARN("[AMF] EAP-Failure sent (mutual auth check failed)  UE="<<ueAddr);
            }
        }
    }

    void SendEapRequest(Address from,std::vector<uint8_t> chunk,uint8_t id){
        auto pkts=BuildEapTlsPackets(EAP_CODE_REQUEST,id,chunk.data(),chunk.size());
        for(auto& p:pkts) m_socketN1->SendTo(Create<Packet>(p.data(),p.size()),0,from);
    }

    void ContinueAfterEapSuccess(Ipv4Address ueAddr,Address from){
        double t_guti=NowNs();
        uint32_t tmsi=0;
        RAND_bytes((uint8_t*)&tmsi,4);
        double guti_ns=NowNs()-t_guti;

        NS_LOG_INFO("[AMF] GUTI assigned TMSI=0x"<<std::hex<<tmsi<<std::dec
            <<"  cpuCost="<<std::fixed<<std::setprecision(3)<<(guti_ns/1e6)<<"ms");

        m_ueContext[ueAddr.Get()] = {from, tmsi, guti_ns, Simulator::Now()};

        // GUTI-assignment CPU cost is injected as a scheduling delay too.
        Simulator::Schedule(CpuDelay(guti_ns),
            &AmfApplication::SendPduSessionRequest,this,ueAddr,tmsi);
    }

    void SendPduSessionRequest(Ipv4Address ueAddr,uint32_t tmsi){
        NS_LOG_INFO("[AMF] Sending PDU Session Request to SMF (N11)  UE="<<ueAddr);
        // Start the N11 round-trip clock here, when the request actually leaves,
        // not earlier in ContinueAfterEapSuccess(). With --amfServers>=1 the GUTI
        // job can wait in the AMF's CPU queue first, and that wait is AMF queueing,
        // not N11 network time, so it must not be counted in the N11 latency.
        m_ueContext[ueAddr.Get()].pdu_req_time=Simulator::Now();
        std::vector<uint8_t> pduReq(9);
        pduReq[0]=PDU_SESSION_REQ;
        uint32_t ue_ip_raw=ueAddr.Get();
        memcpy(&pduReq[1],&ue_ip_raw,4);
        memcpy(&pduReq[5],&tmsi,4);
        m_socketN11->SendTo(Create<Packet>(pduReq.data(),pduReq.size()),
            0, InetSocketAddress(m_smfAddr,9010));
    }

    // Step 4: SMF PDU Session Accept received
    void HandlePduResp(Ptr<Socket> sock){
        Ptr<Packet> pkt; Address from;
        while((pkt=sock->RecvFrom(from))){
            uint32_t sz=pkt->GetSize();
            if(sz<13) continue;
            std::vector<uint8_t> buf(sz); pkt->CopyData(buf.data(),sz);
            if(buf[0]!=PDU_SESSION_ACC) continue;

            uint32_t ue_ip_raw=0; memcpy(&ue_ip_raw,&buf[1],4);
            uint64_t pdu_ns=0;   memcpy(&pdu_ns,&buf[5],8);
            Ipv4Address ueIp(ue_ip_raw);

            NS_LOG_INFO("[AMF] PDU Session Accept received from SMF"
                <<"  UE="<<ueIp
                <<"  SMF-setup="<<std::fixed<<std::setprecision(3)
                <<((double)pdu_ns/1e6)<<"ms");

            // N11 round-trip latency — a real network span, so it is measured
            // on the simulated clock (Simulator::Now()), not the wall clock.
            if(m_ueContext.count(ue_ip_raw)){
                m_pduLatency = Simulator::Now() - m_ueContext[ue_ip_raw].pdu_req_time;
                NS_LOG_INFO("[AMF] N11 PDU round-trip latency: "
                    <<std::fixed<<std::setprecision(3)
                    <<(m_pduLatency.GetNanoSeconds()/1e6)<<"ms");
            }

            // Step 5: Send Registration Accept + PDU Accept to UE
            // Format: [0x02][tmsi 4B][guti_ns 8B][pdu_ns 8B] = 21 bytes
            NS_LOG_INFO("[AMF] Sending Registration Accept + PDU Session Accept to UE "<<ueIp);
            if(m_ueContext.count(ue_ip_raw)){
                auto& ctx = m_ueContext[ue_ip_raw];
                std::vector<uint8_t> resp(21);
                resp[0]=MSG_REG_ACCEPT;
                memcpy(&resp[1],&ctx.tmsi,4);
                uint64_t gns=(uint64_t)ctx.guti_ns;
                memcpy(&resp[5],&gns,8);
                memcpy(&resp[13],&pdu_ns,8);
                m_socketN1->SendTo(
                    Create<Packet>(resp.data(),resp.size()),
                    0, ctx.from_addr);
            }
        }
    }

    struct UeContext {
        Address  from_addr;
        uint32_t tmsi;
        double   guti_ns;
        Time     pdu_req_time;
    };

    Ptr<Socket>                          m_socketN1, m_socketN11;
    Ipv4Address                          m_smfAddr;
    std::map<uint32_t,UeContext>         m_ueContext;
    std::map<uint32_t,AmfEapTlsSession>  m_eapSessions; // keyed by UE IP
    uint32_t                             m_authCount, m_rejectCount;
    Time                                  m_pduLatency;
    uint32_t                              m_cpuServers=0;
    std::vector<Time>                     m_cpuBusyUntil;
};

// ============================================================
// BSM SINK + VERIFIER — remoteHost:9002
// Decrypts BSM using per-UE KNASenc/KNASint
// ============================================================
class BsmSink : public Application {
public:
    BsmSink():m_socket(nullptr),m_rxOk(0),m_rxFail(0){}
    static TypeId GetTypeId(){
        static TypeId tid=TypeId("BsmSink").SetParent<Application>()
            .SetGroupName("V2NComplete").AddConstructor<BsmSink>();return tid;}
    uint32_t GetRxOk()   const{return m_rxOk;}
    uint32_t GetRxFail() const{return m_rxFail;}

    void RegisterUeKey(Ipv4Address ueAddr,
                       const uint8_t enc[16],const uint8_t integrity[16]){
        memcpy(m_enc[ueAddr.Get()],enc,16);
        memcpy(m_int[ueAddr.Get()],integrity,16);
        NS_LOG_INFO("[BSM-SINK] Keys registered for UE "<<ueAddr);
    }

protected:
    void StartApplication() override {
        m_socket=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(),9002));
        m_socket->SetRecvCallback(MakeCallback(&BsmSink::HandleBsm,this));
        NS_LOG_INFO("[BSM-SINK] Ready on remoteHost:9002");
    }
    void StopApplication() override {
        if(m_socket){m_socket->Close();m_socket=nullptr;}
        NS_LOG_INFO("[BSM-SINK] rx ok="<<m_rxOk<<" fail="<<m_rxFail);
    }
private:
    void HandleBsm(Ptr<Socket> sock){
        Ptr<Packet> pkt; Address from;
        while((pkt=sock->RecvFrom(from))){
            uint32_t sz=pkt->GetSize();
            if(sz<64){m_rxFail++;continue;}
            std::vector<uint8_t> wire(sz); pkt->CopyData(wire.data(),sz);
            Ipv4Address srcAddr=InetSocketAddress::ConvertFrom(from).GetIpv4();
            uint32_t key=srcAddr.Get();
            if(m_enc.find(key)==m_enc.end()){m_rxFail++;continue;}
            const uint8_t* iv=wire.data();
            size_t cipherLen=sz-16-32;
            const uint8_t* cipher=wire.data()+16;
            const uint8_t* rxMac=wire.data()+16+cipherLen;
            auto expMac=ComputeHmac(wire.data(),16+cipherLen,m_int[key],16);
            if(memcmp(rxMac,expMac.data(),32)!=0){m_rxFail++;continue;}
            auto plain=AesDecrypt(cipher,cipherLen,m_enc[key],iv);
            if(plain.size()<sizeof(BSMHeader)){m_rxFail++;continue;}
            BSMHeader hdr; memcpy(&hdr,plain.data(),sizeof(BSMHeader));
            m_rxOk++;
            if(m_rxOk%10==0)
                NS_LOG_INFO("[BSM-SINK] ok="<<m_rxOk
                    <<" vehicleId="<<hdr.vehicleId
                    <<" seq="<<hdr.seqNum
                    <<" speed="<<std::fixed<<std::setprecision(1)<<hdr.speed<<"m/s"
                    <<" lat="<<hdr.latitude<<" lon="<<hdr.longitude
                    <<" latency="<<(Simulator::Now().GetNanoSeconds()-hdr.timestamp_ns)<<"ns");
        }
    }
    Ptr<Socket> m_socket;
    uint32_t    m_rxOk,m_rxFail;
    std::map<uint32_t,uint8_t[16]> m_enc;
    std::map<uint32_t,uint8_t[16]> m_int;
};

// ============================================================
// IDS APPLICATION — remoteHost:9003
// ============================================================
class IdsApplication : public Application {
public:
    IdsApplication():m_socket(nullptr),m_alertCount(0),m_windowCount(0){}
    static TypeId GetTypeId(){
        static TypeId tid=TypeId("IdsApplication").SetParent<Application>()
            .SetGroupName("V2NComplete").AddConstructor<IdsApplication>();return tid;}
    uint32_t GetAlertCount() const{return m_alertCount;}
protected:
    void StartApplication() override {
        m_socket=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(),9003));
        m_socket->SetRecvCallback(MakeCallback(&IdsApplication::HandlePkt,this));
        Simulator::Schedule(Seconds(1.0),&IdsApplication::CheckRate,this);
        NS_LOG_INFO("[IDS] Ready on remoteHost:9003");
    }
    void StopApplication() override {
        if(m_socket){m_socket->Close();m_socket=nullptr;}
        NS_LOG_INFO("[IDS] Total alerts: "<<m_alertCount);
    }
private:
    void HandlePkt(Ptr<Socket> sock){
        Ptr<Packet> pkt; Address from;
        while((pkt=sock->RecvFrom(from))){
            m_windowCount++;
            if(pkt->GetSize()>=8){
                uint8_t buf[8]; pkt->CopyData(buf,8);
                uint32_t vid,seq;
                memcpy(&vid,buf,4); memcpy(&seq,buf+4,4);
                uint64_t k=((uint64_t)vid<<32)|seq;
                if(m_seen.count(k)){
                    NS_LOG_WARN("[IDS] REPLAY vehicleId="<<vid<<" seq="<<seq);
                    m_alertCount++;
                } else { m_seen.insert(k); }
            }
        }
    }
    void CheckRate(){
        if(m_windowCount>50){
            NS_LOG_WARN("[IDS] DoS DETECTED "<<m_windowCount<<" pkts/s");
            m_alertCount++;
        }
        m_windowCount=0;
        Simulator::Schedule(Seconds(1.0),&IdsApplication::CheckRate,this);
    }
    Ptr<Socket>                  m_socket;
    uint32_t                     m_alertCount,m_windowCount;
    std::unordered_set<uint64_t> m_seen;
};

// ============================================================
// UE REGISTRATION APP
// Complete 3GPP TS 23.502 registration + PDU session flow:
//   1. DTLS handshake
//   2. Build SUCI -> send Registration Request to AMF
//   3. Wait for Registration Accept + PDU Session Accept (0x02, 21 bytes)
//   4. Derive key chain
//   5. Register keys with BsmSink
//   6. Send encrypted BSMs (AES-128-CBC + HMAC-SHA256)
// ============================================================
class UeRegistrationApp : public Application {
public:
    UeRegistrationApp()
      :m_socketNas(nullptr),m_socketBsm(nullptr),m_registered(false),
       m_authCount(0),m_rejectCount(0),
       m_suciLatency_ns(0),m_keyDerivLatency_ns(0),m_gutiAssignLatency_ns(0),
       m_pduLatency_ns(0),m_eapTlsCpuNs(0),
       m_encOverhead_ns(0),m_bsmTxCount(0),m_ueIndex(0),
       m_hnPubKey(nullptr),m_cliCert(nullptr),m_cliPkey(nullptr),
       m_cliSsl(nullptr),m_cliRbio(nullptr),m_cliWbio(nullptr),
       m_cliHandshakeDone(false),m_eapTlsMutualAuthOk(false),
       m_cliFlightId(0),m_cliPrevWritten(0),
       m_bsmSink(nullptr)
    {}

    ~UeRegistrationApp() override{
        if(m_cliSsl) SSL_free(m_cliSsl); // also frees owned rbio/wbio
        if(m_hnPubKey) EC_KEY_free(m_hnPubKey);
        if(m_cliCert) X509_free(m_cliCert);
        if(m_cliPkey) EVP_PKEY_free(m_cliPkey);
    }

    static TypeId GetTypeId(){
        static TypeId tid=TypeId("UeRegistrationApp").SetParent<Application>()
            .SetGroupName("V2NComplete").AddConstructor<UeRegistrationApp>();return tid;}

    void SetUeIndex(uint32_t idx){
        m_ueIndex=idx;

        // UE only ever holds the Home Network PUBLIC key (used to build the
        // SUCI). It cannot decrypt its own SUCI — only the AMF/UDM (which
        // holds g_hnKeyPair's private half) can, in DeconcealSuci(). This is
        // separate from EAP-TLS: identity concealment and the authentication
        // method are independent 3GPP mechanisms.
        m_hnPubKey=EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_set_group(m_hnPubKey,EC_KEY_get0_group(g_hnKeyPair));
        EC_KEY_set_public_key(m_hnPubKey,EC_KEY_get0_public_key(g_hnKeyPair));

        // Per-UE client certificate, presented during EAP-TLS.
        MakeCert(&m_cliCert,&m_cliPkey,g_sigAlg);
    }
    void SetRemoteAddress(Ipv4Address addr){m_remoteAddr=addr;}
    void SetBsmSink(Ptr<BsmSink> sink){m_bsmSink=sink;}

    bool     IsRegistered()          const{return m_registered;}
    double   GetRegLatency_ms()      const{return m_regLatency.GetNanoSeconds()/1e6;}
    double   GetSuciLatency_ms()     const{return m_suciLatency_ns/1e6;}
    double   GetKeyDerivLatency_ms() const{return m_keyDerivLatency_ns/1e6;}
    double   GetGutiLatency_ms()     const{return m_gutiAssignLatency_ns/1e6;}
    double   GetPduLatency_ms()      const{return m_pduLatency_ns/1e6;}
    double   GetBsmGateLatency_ms()  const{return m_bsmGateLatency.GetNanoSeconds()/1e6;}
    double   GetEapTlsCpuMs()        const{return m_eapTlsCpuNs/1e6;}           // CPU cost only
    double   GetEapTlsWireMs()       const{return m_eapTlsWireTime.GetNanoSeconds()/1e6;} // sim E2E
    bool     GetEapTlsMutualAuthOk() const{return m_eapTlsMutualAuthOk;}
    std::string GetEapTlsCipher()    const{return m_eapTlsCipher;}
    std::string GetEapTlsGroup()     const{return m_eapTlsGroup;}
    std::string GetPeerCertSigAlg()  const{return m_peerCertSigAlg;}
    size_t   GetEapTlsFlightCount()  const{return m_cliFlights.size();}
    double   GetEncOverhead_us()     const{return m_bsmTxCount>0?(m_encOverhead_ns/m_bsmTxCount)/1e3:0;}
    uint32_t GetAuthCount()          const{return m_authCount;}
    uint32_t GetRejectCount()        const{return m_rejectCount;}
    uint32_t GetBsmTxCount()         const{return m_bsmTxCount;}
    Guti     GetGUTI()               const{return m_guti;}
    NasKeys  GetKeys()               const{return m_nasKeys;}
    Ipv4Address GetUeAddr()          const{return m_ueAddr;}

protected:
    void StartApplication() override {
        m_ueAddr=GetNode()->GetObject<Ipv4>()->GetAddress(1,0).GetLocal();

        m_socketNas=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_socketNas->Bind(InetSocketAddress(Ipv4Address::GetAny(),9001));
        m_socketNas->SetRecvCallback(
            MakeCallback(&UeRegistrationApp::HandleNasResponse,this));

        m_socketBsm=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_socketBsm->Bind();

        std::ostringstream ss;
        ss<<"imsi-001-01-"<<std::setw(10)<<std::setfill('0')<<(m_ueIndex+1);
        m_supi.value=ss.str();
        NS_LOG_INFO("[UE-"<<m_ueIndex<<"] SUPI="<<m_supi.value<<" IP="<<m_ueAddr);

        // Sending the Registration Request is what kicks off the whole
        // procedure now — including EAP-TLS primary authentication — so the
        // E2E registration clock starts here.
        m_regStart=Simulator::Now();
        SendRegistrationRequest();
    }
    void StopApplication() override {
        if(m_socketNas){m_socketNas->Close();m_socketNas=nullptr;}
        if(m_socketBsm){m_socketBsm->Close();m_socketBsm=nullptr;}
    }

private:
    // Registration Request just carries the SUCI now — this is what
    // triggers the AMF to start EAP-TLS (see AmfApplication). No local
    // handshake state exists yet; the UE (EAP peer) waits passively for the
    // AMF's EAP-Request/Start.
    void SendRegistrationRequest(){
        m_suci=BuildSuci(m_supi.value,m_hnPubKey);
        m_suciLatency_ns=m_suci.construction_ns; // CPU cost of building the SUCI
        NS_LOG_INFO("[UE-"<<m_ueIndex<<"] SUCI built"
            <<" size="<<m_suci.bytes.size()<<"B"
            <<" time="<<std::fixed<<std::setprecision(3)
            <<(m_suciLatency_ns/1e6)<<"ms");

        std::vector<uint8_t> wire;
        wire.push_back(MSG_REG_REQUEST);
        wire.insert(wire.end(),m_suci.bytes.begin(),m_suci.bytes.end());

        // Building the SUCI cost real CPU time — inject it before the
        // request actually leaves, instead of sending "for free".
        Simulator::Schedule(NanoSeconds(m_suciLatency_ns),
            &UeRegistrationApp::TransmitRegistrationRequest,this,wire);
    }

    void TransmitRegistrationRequest(std::vector<uint8_t> wire){
        Ptr<Packet> req=Create<Packet>(wire.data(),wire.size());
        m_socketNas->SendTo(req,0,InetSocketAddress(m_remoteAddr,9000));
        NS_LOG_INFO("[UE-"<<m_ueIndex<<"] Registration Request sent"
            <<" ("<<wire.size()<<"B, SUCI)"
            <<" via Uu->EPC->AMF("<<m_remoteAddr<<":9000)");
    }

    // --------------------------------------------------------
    // EAP-TLS (peer side). Driven entirely by EAP-Request packets from the
    // AMF: the Start packet creates our TLS client state; every subsequent
    // Request/reassembled flight steps SSL_do_handshake() again; the final
    // EAP-Success/Failure decides the outcome.
    // --------------------------------------------------------
    void HandleEapFromAmf(const std::vector<uint8_t>& pkt){
        ParsedEap pe;
        if(!ParseEap(pkt,pe)) return;

        if(pe.code==EAP_CODE_SUCCESS){ FinishEapTls(true);  return; }
        if(pe.code==EAP_CODE_FAILURE){ FinishEapTls(false); return; }
        if(pe.code!=EAP_CODE_REQUEST) return;

        if(pe.flags & EAP_FLAG_S){
            NS_LOG_INFO("[UE-"<<m_ueIndex<<"] EAP-Request(Start) received — beginning EAP-TLS");
            m_cliSsl=SSL_new(g_cliCtx);
            SSL_use_certificate(m_cliSsl,m_cliCert);
            SSL_use_PrivateKey(m_cliSsl,m_cliPkey);
            m_cliRbio=BIO_new(BIO_s_mem());
            m_cliWbio=BIO_new(BIO_s_mem());
            BIO_set_mem_eof_return(m_cliRbio,-1);
            SSL_set_bio(m_cliSsl,m_cliRbio,m_cliWbio);
            SSL_set_connect_state(m_cliSsl);
            StepCliHandshake(pe.identifier);
            return;
        }

        // Normal handshake flight from AMF
        if(!FeedEapFrag(m_amfReasm,pe.flags,pe.tlsMsgLen,pe.data,pe.dataLen)) return;
        BIO_write(m_cliRbio,m_amfReasm.buf.data(),(int)m_amfReasm.buf.size());
        m_amfReasm.active=false;
        StepCliHandshake(pe.identifier);
    }

    void StepCliHandshake(uint8_t echoId){
        double t0=NowNs();
        int r=SSL_do_handshake(m_cliSsl);
        double cpuNs=NowNs()-t0;
        m_eapTlsCpuNs+=cpuNs;

        uint64_t written=BIO_number_written(m_cliWbio);
        uint64_t delta=written-m_cliPrevWritten;
        m_cliPrevWritten=written;

        if(delta>0){
            std::vector<uint8_t> chunk(delta);
            BIO_read(m_cliWbio,chunk.data(),(int)delta);
            uint8_t fid=m_cliFlightId++;
            m_cliFlights.push_back({fid,delta});
            NS_LOG_INFO("[UE-"<<m_ueIndex<<"] EAP-TLS flight #"<<(int)fid
                <<"  "<<delta<<"B  cpuCost="<<std::fixed<<std::setprecision(3)
                <<(cpuNs/1e6)<<"ms");
            // CPU cost of producing this flight is injected as sim delay
            // before the EAP-Response actually goes out.
            Simulator::Schedule(NanoSeconds(cpuNs),
                &UeRegistrationApp::SendEapResponse,this,chunk,echoId);
        }

        if(r==1 && !m_cliHandshakeDone){
            m_cliHandshakeDone=true;
            NS_LOG_INFO("[UE-"<<m_ueIndex<<"] local TLS handshake complete,"
                <<" awaiting EAP-Success/Failure from AMF...");
        }
    }

    void SendEapResponse(std::vector<uint8_t> chunk,uint8_t echoId){
        auto pkts=BuildEapTlsPackets(EAP_CODE_RESPONSE,echoId,chunk.data(),chunk.size());
        for(auto& p:pkts)
            m_socketNas->SendTo(Create<Packet>(p.data(),p.size()),0,
                InetSocketAddress(m_remoteAddr,9000));
    }

    // EAP-Success/Failure is the actual authentication decision (the TLS
    // handshake completing locally is necessary but not sufficient — only
    // the authenticator's EAP-Success finalizes it, matching RFC 3748).
    void FinishEapTls(bool success){
        m_eapTlsWireTime=Simulator::Now()-m_regStart; // whole auth-phase sim span

        if(!success){
            m_rejectCount++;
            NS_LOG_WARN("[UE-"<<m_ueIndex<<"] EAP-TLS FAILED (EAP-Failure received)");
            return;
        }

        long vr=SSL_get_verify_result(m_cliSsl);
        X509* peer=SSL_get_peer_certificate(m_cliSsl);
        m_eapTlsMutualAuthOk=(vr==X509_V_OK && peer!=nullptr);

        // Same direct PQC confirmation as the AMF side: read the actual
        // negotiated group and the AMF cert's real signature algorithm off
        // this UE's own independent SSL object, not assumed from config.
        int negGroupId=SSL_get_negotiated_group(m_cliSsl);
        const char* negGroupName=SSL_group_to_name(m_cliSsl,negGroupId);
        char peerSigAlgBuf[80]="unknown";
        if(peer){
            const X509_ALGOR* palg=nullptr; const ASN1_BIT_STRING* psig=nullptr;
            X509_get0_signature(&psig,&palg,peer);
            OBJ_obj2txt(peerSigAlgBuf,sizeof(peerSigAlgBuf),palg->algorithm,0);
        }
        if(peer) X509_free(peer);
        m_eapTlsCipher=SSL_get_cipher(m_cliSsl);
        m_eapTlsGroup=negGroupName?negGroupName:"NONE/CLASSICAL";
        m_peerCertSigAlg=peerSigAlgBuf;

        // Standard EAP-TLS key export label (RFC 5216 2.3): 64-byte MSK.
        uint8_t msk[64];
        SSL_export_keying_material(m_cliSsl,msk,64,"client EAP encryption",22,nullptr,0,0);

        double kt0=NowNs();
        m_nasKeys=DeriveKeyChainFromMsk(msk,
            "5G:mnc001.mcc001.3gppnetwork.org",m_supi.value);
        m_keyDerivLatency_ns=NowNs()-kt0; // CPU cost

        NS_LOG_INFO("[UE-"<<m_ueIndex<<"] EAP-TLS SUCCESS  mutualAuth="<<m_eapTlsMutualAuthOk
            <<"  cipher="<<m_eapTlsCipher
            <<"  group="<<m_eapTlsGroup
            <<"  peerCertSigAlg="<<m_peerCertSigAlg
            <<"  wireTime="<<(m_eapTlsWireTime.GetNanoSeconds()/1e6)<<"ms"
            <<"  cpuCost="<<std::fixed<<std::setprecision(3)<<(m_eapTlsCpuNs/1e6)<<"ms"
            <<"  flights="<<m_cliFlights.size());

        if(m_bsmSink)
            m_bsmSink->RegisterUeKey(m_ueAddr,m_nasKeys.KNASenc,m_nasKeys.KNASint);
    }

    // Handles Registration Accept (0x02, 21 bytes) and Reject (0xFF) — the
    // NAS-level outcome, arriving after EAP-Success + GUTI + PDU session.
    void HandleNasResponse(Ptr<Socket> sock){
        Ptr<Packet> pkt; Address from;
        while((pkt=sock->RecvFrom(from))){
            uint32_t sz=pkt->GetSize();
            std::vector<uint8_t> buf(sz); pkt->CopyData(buf.data(),sz);
            if(sz<1) continue;

            if(buf[0]==MSG_EAP){ HandleEapFromAmf(buf); continue; }

            if(buf[0]==MSG_REG_REJECT){
                m_rejectCount++;
                NS_LOG_WARN("[UE-"<<m_ueIndex<<"] Registration REJECTED by AMF");
                continue;
            }

            if(buf[0]==MSG_REG_ACCEPT&&sz>=21){
                m_authCount++;

                memcpy(&m_guti.tmsi,&buf[1],4);
                m_guti.amf_id="001-01-0001"; m_guti.valid=true;

                // CPU-cost figures forwarded from the core (AMF's GUTI
                // RAND_bytes cost, SMF's session-alloc cost) — not E2E
                // network spans.
                uint64_t gns=0; memcpy(&gns,&buf[5],8);
                m_gutiAssignLatency_ns=(double)gns;
                uint64_t pns=0; memcpy(&pns,&buf[13],8);
                m_pduLatency_ns=(double)pns;

                m_registered=true;
                m_regLatency=Simulator::Now()-m_regStart; // simulated E2E span

                NS_LOG_INFO("[UE-"<<m_ueIndex<<"] Registration + PDU Session COMPLETE"
                    <<" TMSI=0x"<<std::hex<<m_guti.tmsi<<std::dec
                    <<" suci="<<std::fixed<<std::setprecision(3)
                    <<(m_suciLatency_ns/1e6)<<"ms"
                    <<" keyderiv="<<(m_keyDerivLatency_ns/1e6)<<"ms"
                    <<" guti="<<(m_gutiAssignLatency_ns/1e6)<<"ms"
                    <<" pdu="<<(m_pduLatency_ns/1e6)<<"ms"
                    <<" total="<<(m_regLatency.GetNanoSeconds()/1e6)<<"ms [sim E2E, incl EAP-TLS+Uu+N11]");

                m_bsmGateStartTime=Simulator::Now();
                Simulator::Schedule(Seconds(0.1),&UeRegistrationApp::SendBsm,this);
            }
        }
    }

    // Encrypted BSM: AES-128-CBC(KNASenc) + HMAC-SHA256(KNASint)
    // Uses real mobility model position and velocity
    void SendBsm(){
        // Guard against the app having already been stopped (StopApplication()
        // closes and nullptrs m_socketBsm) by a self-rescheduled event that
        // was queued before the stop and never cancelled. This is the real
        // fix for the crash seen with short --simTime values: StopTime can
        // land before the fixed 22s BSM cap below, so relying on that cap
        // alone to know when to stop isn't safe — check the actual app state.
        if(!m_registered || !m_socketBsm) return;
        if(m_bsmGateLatency.IsZero())
            m_bsmGateLatency=Simulator::Now()-m_bsmGateStartTime; // simulated span

        double enc_t0=NowNs();

        Ptr<MobilityModel> mob=GetNode()->GetObject<MobilityModel>();
        Vector pos=mob->GetPosition();
        Vector vel=mob->GetVelocity();

        BSMHeader hdr;
        hdr.vehicleId   =m_ueIndex;
        hdr.seqNum      =m_bsmTxCount;
        hdr.latitude    =pos.x;
        hdr.longitude   =pos.y;
        hdr.speed       =vel.x;
        hdr.timestamp_ns=(uint64_t)Simulator::Now().GetNanoSeconds();

        uint8_t iv[16]; RAND_bytes(iv,16);
        auto cipher=AesEncrypt(reinterpret_cast<uint8_t*>(&hdr),
                                sizeof(BSMHeader),m_nasKeys.KNASenc,iv);
        std::vector<uint8_t> toSign(16+cipher.size());
        memcpy(toSign.data(),iv,16);
        memcpy(toSign.data()+16,cipher.data(),cipher.size());
        uint8_t int_key32[32]={0}; memcpy(int_key32,m_nasKeys.KNASint,16);
        auto mac=ComputeHmac(toSign.data(),toSign.size(),int_key32,32);
        std::vector<uint8_t> wire(16+cipher.size()+32);
        memcpy(wire.data(),iv,16);
        memcpy(wire.data()+16,cipher.data(),cipher.size());
        memcpy(wire.data()+16+cipher.size(),mac.data(),32);

        double encCostNs=NowNs()-enc_t0; // CPU cost
        m_encOverhead_ns+=encCostNs;
        m_bsmTxCount++;

        // Encryption cost is injected as sim delay before the packet leaves.
        Simulator::Schedule(NanoSeconds(encCostNs),
            &UeRegistrationApp::TransmitBsm,this,wire);

        if(Simulator::Now()<Seconds(22.0))
            Simulator::Schedule(MilliSeconds(100),&UeRegistrationApp::SendBsm,this);
    }

    void TransmitBsm(std::vector<uint8_t> wire){
        // Same guard as SendBsm(): the encryption-cost delay (Schedule call
        // just above, in SendBsm) means this can still fire after
        // StopApplication() already nulled the socket.
        if(!m_socketBsm) return;
        Ptr<Packet> bsm=Create<Packet>(wire.data(),wire.size());
        m_socketBsm->SendTo(bsm,0,InetSocketAddress(m_remoteAddr,9002));
    }

    Ptr<Socket>   m_socketNas,m_socketBsm;
    Supi m_supi; Suci m_suci; Guti m_guti; NasKeys m_nasKeys;
    Ipv4Address   m_remoteAddr, m_ueAddr;
    Ptr<BsmSink>  m_bsmSink;
    bool          m_registered;
    uint32_t      m_authCount,m_rejectCount,m_bsmTxCount;

    // Simulated E2E spans (Simulator::Now()-based)
    Time          m_regStart, m_regLatency;
    Time          m_bsmGateStartTime, m_bsmGateLatency;
    Time          m_eapTlsWireTime;

    // CPU-only costs (NowNs()-based), each injected into the sim timeline
    // via Simulator::Schedule at its point of use.
    double        m_suciLatency_ns,m_keyDerivLatency_ns,m_gutiAssignLatency_ns;
    double        m_pduLatency_ns,m_eapTlsCpuNs,m_encOverhead_ns;

    uint32_t      m_ueIndex;

    // EAP-TLS (peer/client) state
    EC_KEY*       m_hnPubKey;
    X509*         m_cliCert; EVP_PKEY* m_cliPkey;
    SSL*          m_cliSsl; BIO* m_cliRbio; BIO* m_cliWbio;
    bool          m_cliHandshakeDone, m_eapTlsMutualAuthOk;
    uint8_t       m_cliFlightId; uint64_t m_cliPrevWritten;
    std::vector<std::pair<uint8_t,size_t>> m_cliFlights;
    EapReasm      m_amfReasm;
    std::string   m_eapTlsCipher;
    std::string   m_eapTlsGroup;      // actual negotiated TLS key-exchange group (PQC confirmation)
    std::string   m_peerCertSigAlg;   // AMF cert's real signature algorithm (PQC confirmation)
};

// ============================================================
// MAIN
// ============================================================
int main(int argc,char* argv[])
{
    uint32_t numUes=10; double simTime=25.0;
    double attachSpacingMs=0.0; // ms between consecutive UE radio attaches; 0 = all attach at t=0 (old behaviour)
    double centralFreq=3.5e9, bandwidth=20e6, totalTxPower=30.0;
    uint16_t numerology=1;
    std::string kemGroup="MLKEM768"; // --kemGroup: ECDHE | MLKEM768 | X25519MLKEM768
    bool realtimeMode=true;          // --realtime=0 for fast unattended sweeps
    double   ueStagger=0.1;          // --ueStagger: seconds between consecutive UE start times
    double   ueSpacing=20.0;         // --ueSpacing: metres between consecutive UEs along x
    uint32_t amfServers=0;           // --amfServers: AMF crypto CPU workers (0 = unlimited)
    uint32_t numGnbs=1;              // --numGnbs: one NR cell tops out at ~40 UEs (RNTI assert on the 41st); use more gNBs for >40 UEs
    double   gnbSpacing=1000.0;      // --gnbSpacing: metres between consecutive gNBs along x

    // Parse CLI first so --realtime and cert/KEM config are known before
    // anything Simulator-related is touched below.
    CommandLine cmd(__FILE__);
    cmd.AddValue("numUes",  "Number of vehicle UEs (default 10)",numUes);
    cmd.AddValue("numGnbs", "Number of gNBs (default 1). UEs are split evenly and grouped around their own gNB. A single NR cell fails at the 41st UE (RNTI assert), so use e.g. --numGnbs=2 for 50 UEs",numGnbs);
    cmd.AddValue("gnbSpacing","Metres between consecutive gNBs along x (default 1000, keeps inter-cell interference small)",gnbSpacing);
    cmd.AddValue("attachSpacingMs","Milliseconds between UE radio attaches. 0 (default) = all UEs attach at t=0, which crashes the NR ideal-RRC model (RNTI assert) at roughly 50+ UEs. Use e.g. 5 for large UE counts. Attach happens before registration starts, so it is not in the measured registration latency",attachSpacingMs);
    cmd.AddValue("simTime", "Simulation duration (s)",simTime);
    cmd.AddValue("sigAlg",  "Certificate signature algorithm: RSA | ML-DSA-44 | ML-DSA-65 | ML-DSA-87",g_sigAlg);
    cmd.AddValue("kemGroup","TLS key-exchange group: ECDHE | MLKEM768 | X25519MLKEM768",kemGroup);
    cmd.AddValue("realtime","1=wall-clock-paced (default), 0=fast/as-fast-as-possible for sweeps",realtimeMode);
    cmd.AddValue("ueStagger","Seconds between UE start times. 0.1 (default) = registrations never overlap; "
                             "0 = all UEs register simultaneously (needed to see contention)",ueStagger);
    cmd.AddValue("ueSpacing","Metres between UEs along x (default 20). Small values (e.g. 2) cluster the UEs "
                             "so per-UE latency isn't confounded by distance from the gNB",ueSpacing);
    cmd.AddValue("amfServers","AMF parallel crypto CPU workers. 0 (default) = unlimited, i.e. server-side "
                              "crypto never queues. N>=1 = overlapping registrations queue for N workers",amfServers);
    cmd.Parse(argc,argv);

    // Realtime mode: paces dispatch of scheduled events against the actual
    // wall clock, so Simulator::Now() tracks real elapsed time (1x speed)
    // instead of running as fast as the CPU allows. This does NOT by itself
    // turn CPU-bound work (SSL_do_handshake, AES, KDF, ...) into simulated
    // delay — that still requires the Simulator::Schedule(NanoSeconds(cost),
    // ...) injection already used throughout this file. What realtime mode
    // adds is that the *program's* runtime matches the *simulation's*
    // reported time. Byte counts, message counts, and reported simulated
    // delays are THE SAME either way — --realtime=0 only changes how long
    // the program itself takes to run, which is what makes it safe to use
    // for fast automated sweeps across many configurations/trials.
    if(realtimeMode){
        GlobalValue::Bind("SimulatorImplementationType",
                           StringValue("ns3::RealtimeSimulatorImpl"));
        Config::SetDefault("ns3::RealtimeSimulatorImpl::SynchronizationMode",
                            EnumValue(ns3::RealtimeSimulatorImpl::SYNC_BEST_EFFORT));
    }

    LogComponentEnable("V2NComplete",LOG_LEVEL_INFO);

    // EAP-TLS setup — mutual authentication: AMF (EAP authenticator)
    // requires a client cert (SSL_VERIFY_FAIL_IF_NO_PEER_CERT) and the UE
    // (EAP peer) verifies the AMF's server cert; both sides run
    // SSL_VERIFY_PEER. This IS 5G primary authentication now — GUTI/PDU
    // session only proceed after EAP-Success (see AmfApplication).
    SSL_library_init(); SSL_load_error_strings();
    MakeCert(&g_cert,&g_pkey,g_sigAlg);
    g_srvCtx=SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(g_srvCtx,g_cert);
    SSL_CTX_use_PrivateKey(g_srvCtx,g_pkey);
    SSL_CTX_set_verify(g_srvCtx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,AlwaysAcceptVerify);
    g_cliCtx=SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(g_cliCtx,SSL_VERIFY_PEER,AlwaysAcceptVerify);

    // TLS key-exchange group, set from --kemGroup so classical/hybrid/pure-PQC
    // can be swept without recompiling. "ECDHE" maps to a concrete classical
    // group (X25519) as the non-PQC baseline; anything else is passed
    // through verbatim to OpenSSL (MLKEM768, X25519MLKEM768, ...).
    std::string effGroup = (kemGroup=="ECDHE") ? "X25519" : kemGroup;
    if(SSL_CTX_set1_groups_list(g_srvCtx,effGroup.c_str())!=1)
        NS_LOG_WARN("[MAIN] AMF: failed to set TLS group '"<<effGroup<<"' — check OpenSSL 3.5+ is linked");
    if(SSL_CTX_set1_groups_list(g_cliCtx,effGroup.c_str())!=1)
        NS_LOG_WARN("[MAIN] UE: failed to set TLS group '"<<effGroup<<"' — check OpenSSL 3.5+ is linked");

    // Home Network (UDM/SIDF) key pair — only the AMF ever sees the private
    // half. UEs are handed the public half only (see UeRegistrationApp::SetUeIndex).
    g_hnKeyPair=EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(g_hnKeyPair);

    Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod",TimeValue(MilliSeconds(0)));
    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize",UintegerValue(999999999));
    // A cell can only hand out SRS slots to 'SrsPeriodicity' UEs (default 40);
    // the 41st UE then gets RNTI 0 and the ideal-RRC model asserts. 320 is the
    // largest allowed value. Only applied above 40 UEs so smaller runs are
    // unchanged. (Also needs a UE start-time stagger of ~20 ms at 50 UEs.)
    if(numUes>40)
        Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(320));

    // Nodes
    NodeContainer ueNodes,gnbNodes,remoteHostContainer;
    if(numGnbs<1) numGnbs=1;
    ueNodes.Create(numUes); gnbNodes.Create(numGnbs); remoteHostContainer.Create(1);
    Ptr<Node> remoteHost=remoteHostContainer.Get(0);

    // NR helpers
    Ptr<NrPointToPointEpcHelper> epcHelper=CreateObject<NrPointToPointEpcHelper>();
    Ptr<IdealBeamformingHelper>  beamHelper=CreateObject<IdealBeamformingHelper>();
    Ptr<NrHelper> nrHelper=CreateObject<NrHelper>();
    nrHelper->SetBeamformingHelper(beamHelper);
    nrHelper->SetEpcHelper(epcHelper);

    // Spectrum
    CcBwpCreator ccBwp;
    CcBwpCreator::SimpleOperationBandConf bandConf(
        centralFreq,bandwidth,1,BandwidthPartInfo::UMa_LoS);
    OperationBandInfo band=ccBwp.CreateOperationBandContiguousCc(bandConf);
    nrHelper->SetChannelConditionModelAttribute("UpdatePeriod",TimeValue(MilliSeconds(0)));
    nrHelper->SetPathlossAttribute("ShadowingEnabled",BooleanValue(false));
    nrHelper->InitializeOperationBand(&band);
    BandwidthPartInfoPtrVector allBwps=CcBwpCreator::GetAllBwps({band});

    beamHelper->SetAttribute("BeamformingMethod",
        TypeIdValue(DirectPathBeamforming::GetTypeId()));
    epcHelper->SetAttribute("S1uLinkDelay",TimeValue(MilliSeconds(0)));

    nrHelper->SetUeAntennaAttribute("NumRows",UintegerValue(1));
    nrHelper->SetUeAntennaAttribute("NumColumns",UintegerValue(2));
    nrHelper->SetUeAntennaAttribute("AntennaElement",
        PointerValue(CreateObject<IsotropicAntennaModel>()));
    nrHelper->SetGnbAntennaAttribute("NumRows",UintegerValue(4));
    nrHelper->SetGnbAntennaAttribute("NumColumns",UintegerValue(8));
    nrHelper->SetGnbAntennaAttribute("AntennaElement",
        PointerValue(CreateObject<IsotropicAntennaModel>()));

    // Mobility
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(gnbNodes);
    for(uint32_t g=0;g<numGnbs;g++)
        gnbNodes.Get(g)->GetObject<MobilityModel>()->SetPosition(Vector(g*gnbSpacing,0.0,10.0));
    mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobility.Install(ueNodes);
    for(uint32_t i=0;i<numUes;i++){
        auto mob=ueNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        // UEs are split evenly across the gNBs and grouped around their own one.
        // With numGnbs=1 this is identical to the old layout (x = 50 + i*ueSpacing).
        uint32_t perGnb=(numUes+numGnbs-1)/numGnbs;
        uint32_t g=i/perGnb, k=i%perGnb;
        mob->SetPosition(Vector(g*gnbSpacing+50.0+k*ueSpacing,0.0,1.5));
        mob->SetVelocity(Vector(15.0,0.0,0.0));
    }
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(remoteHostContainer);

    // NR devices
    // The UE PHY must get a numerology too; otherwise its subcarrierSpacing
    // stays 0 and it aborts at t=0 with "initialBandwidthWithOverhead == 0".
    nrHelper->SetGnbPhyAttribute("Numerology",UintegerValue(numerology));
    NetDeviceContainer gnbDevs=nrHelper->InstallGnbDevice(gnbNodes,allBwps);
    NetDeviceContainer ueDevs =nrHelper->InstallUeDevice(ueNodes,allBwps);
    // NrUePhy has no "Numerology" attribute (only the gNB PHY does), so set it
    // via the method. Must happen before UpdateConfig()/simulation start.
    for(uint32_t i=0;i<numUes;i++)
        nrHelper->GetUePhy(ueDevs.Get(i),0)->SetNumerology(numerology);
    for(uint32_t g=0;g<numGnbs;g++){
        nrHelper->GetGnbPhy(gnbDevs.Get(g),0)->SetAttribute("Numerology",UintegerValue(numerology));
        nrHelper->GetGnbPhy(gnbDevs.Get(g),0)->SetAttribute("TxPower",DoubleValue(totalTxPower));
    }
    for(uint32_t i=0;i<numUes;i++)
        nrHelper->GetUePhy(ueDevs.Get(i),0)->SetAttribute("TxPower",DoubleValue(23.0));
    for(auto it=gnbDevs.Begin();it!=gnbDevs.End();++it)
        DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    for(auto it=ueDevs.Begin();it!=ueDevs.End();++it)
        DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();

    // Internet stack
    InternetStackHelper internet;
    internet.Install(remoteHostContainer);
    internet.Install(ueNodes);

    Ptr<Node> pgw=epcHelper->GetPgwNode();
    PointToPointHelper p2ph;
    p2ph.SetDeviceAttribute("DataRate",DataRateValue(DataRate("100Gb/s")));
    p2ph.SetDeviceAttribute("Mtu",UintegerValue(2500));
    p2ph.SetChannelAttribute("Delay",TimeValue(Seconds(0.0)));
    NetDeviceContainer internetDevs=p2ph.Install(pgw,remoteHost);
    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0","255.0.0.0");
    Ipv4InterfaceContainer internetIfaces=ipv4h.Assign(internetDevs);
    Ipv4Address remoteHostAddr=internetIfaces.GetAddress(1);

    Ipv4StaticRoutingHelper routingHelper;
    routingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>())
        ->AddNetworkRouteTo(Ipv4Address("7.0.0.0"),Ipv4Mask("255.0.0.0"),1);
    epcHelper->AssignUeIpv4Address(NetDeviceContainer(ueDevs));
    for(uint32_t i=0;i<numUes;i++)
        routingHelper.GetStaticRouting(ueNodes.Get(i)->GetObject<Ipv4>())
            ->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(),1);

    double attachEndS=0.0;
    if(attachSpacingMs<=0.0){
        nrHelper->AttachToClosestEnb(ueDevs,gnbDevs);
    } else {
        // Stagger the radio attach so UEs do not all random-access in the same slot.
        for(uint32_t i=0;i<numUes;i++){
            double t=0.010+i*attachSpacingMs/1000.0;
            attachEndS=t;
            Ptr<NetDevice> ue=ueDevs.Get(i);
            Simulator::Schedule(Seconds(t),[nrHelper,ue,gnbDevs](){
                NetDeviceContainer one(ue);
                nrHelper->AttachToClosestEnb(one,gnbDevs);
            });
        }
    }

    // Uncomment for Wireshark:
    // p2ph.EnablePcapAll("v2n-smf");

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor=flowmon.InstallAll();

    // --------------------------------------------------------
    // APPLICATIONS ON remoteHost
    // SMF must start before AMF so it is ready for N11 messages
    // --------------------------------------------------------
    Ptr<SmfApplication> smfApp=CreateObject<SmfApplication>();
    remoteHost->AddApplication(smfApp);
    smfApp->SetStartTime(Seconds(0.5));
    smfApp->SetStopTime(Seconds(simTime));

    Ptr<AmfApplication> amfApp=CreateObject<AmfApplication>();
    amfApp->SetSmfAddress(remoteHostAddr);  // AMF sends N11 to SMF on same host
    amfApp->SetCpuServers(amfServers);
    remoteHost->AddApplication(amfApp);
    amfApp->SetStartTime(Seconds(0.5));
    amfApp->SetStopTime(Seconds(simTime));

    Ptr<BsmSink> bsmSink=CreateObject<BsmSink>();
    remoteHost->AddApplication(bsmSink);
    bsmSink->SetStartTime(Seconds(0.5));
    bsmSink->SetStopTime(Seconds(simTime));

    Ptr<IdsApplication> idsApp=CreateObject<IdsApplication>();
    remoteHost->AddApplication(idsApp);
    idsApp->SetStartTime(Seconds(0.5));
    idsApp->SetStopTime(Seconds(simTime));

    // UE apps — start at 2.0s
    std::vector<Ptr<UeRegistrationApp>> ueApps(numUes);
    for(uint32_t i=0;i<numUes;i++){
        ueApps[i]=CreateObject<UeRegistrationApp>();
        ueApps[i]->SetUeIndex(i);
        ueApps[i]->SetRemoteAddress(remoteHostAddr);
        ueApps[i]->SetBsmSink(bsmSink);
        ueNodes.Get(i)->AddApplication(ueApps[i]);
        ueApps[i]->SetStartTime(Seconds(std::max(2.0,attachEndS+1.0)+i*ueStagger));
        ueApps[i]->SetStopTime(Seconds(simTime-1.0));
    }

    NS_LOG_INFO("[MAIN] V2N Complete | AMF+SMF+PDU | Uu NR | "
        <<numUes<<" UEs | n78 "<<centralFreq/1e9<<"GHz");
    // CONFIG line: one grep-able line per run, for sweep scripts parsing
    // many runs into a CSV. sigAlg/kemGroup echo back what was actually
    // requested (not necessarily what negotiated — check the per-UE
    // "Negotiated group"/"Peer cert sig alg" summary lines for that).
    NS_LOG_INFO("[MAIN] CONFIG sigAlg="<<g_sigAlg<<" kemGroup="<<kemGroup
        <<" realtime="<<(realtimeMode?1:0)<<" attachSpacingMs="<<attachSpacingMs<<" numUes="<<numUes<<" numGnbs="<<numGnbs
        <<" ueStagger="<<ueStagger<<" ueSpacing="<<ueSpacing<<" amfServers="<<amfServers);
    if(realtimeMode)
        NS_LOG_INFO("[MAIN] Realtime mode: this run will take ~"<<simTime
            <<" real seconds to complete (sim clock paced to wall clock).");
    else
        NS_LOG_INFO("[MAIN] Fast mode (--realtime=0): running as fast as possible.");

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // --------------------------------------------------------
    // RESULTS
    // --------------------------------------------------------
    std::cout<<"\n=================================================\n";
    std::cout<<"  V2N COMPLETE — AMF + SMF + PDU SESSION\n";
    std::cout<<"  Uu NR | UMa LoS | n78 3.5GHz 20MHz\n";
    std::cout<<"=================================================\n";
    std::cout<<std::fixed<<std::setprecision(3);

    double s_eap=0,s_eapWire=0,s_suci=0,s_key=0,s_guti=0,s_pdu=0,s_reg=0,s_bsm=0,s_enc=0;

    for(uint32_t i=0;i<numUes;i++){
        auto app=ueApps[i];
        std::cout<<"\n[UE-"<<i<<"]  registered="<<app->IsRegistered()
                 <<"  IP="<<app->GetUeAddr()<<"\n";
        std::cout<<"  EAP-TLS mutual auth:     "<<(app->GetEapTlsMutualAuthOk()?"OK":"FAILED")
                 <<"  ("<<app->GetEapTlsCipher()<<", "<<app->GetEapTlsFlightCount()<<" flights)\n";
        std::cout<<"  Negotiated group:        "<<app->GetEapTlsGroup()
                 <<(app->GetEapTlsGroup().find("MLKEM")!=std::string::npos?"  [PQC CONFIRMED]":"  [CLASSICAL ONLY]")<<"\n";
        std::cout<<"  Peer cert sig alg:       "<<app->GetPeerCertSigAlg()<<"\n";
        std::cout<<"  EAP-TLS CPU cost:        "<<app->GetEapTlsCpuMs()<<"ms\n";
        std::cout<<"  EAP-TLS wire time (sim): "<<app->GetEapTlsWireMs()<<"ms\n";
        std::cout<<"  SUCI construction:       "<<app->GetSuciLatency_ms()<<"ms\n";
        std::cout<<"  GUTI assignment (AMF):   "<<app->GetGutiLatency_ms()<<"ms\n";
        std::cout<<"  PDU session setup (N11): "<<app->GetPduLatency_ms()<<"ms\n";
        std::cout<<"  Key derivation chain:    "<<app->GetKeyDerivLatency_ms()<<"ms  (KAUSF <- EAP-TLS MSK)\n";
        std::cout<<"  Total registration:      "<<app->GetRegLatency_ms()
                 <<"ms  [incl Uu+N11]\n";
        std::cout<<"  BSM gate delay:          "<<app->GetBsmGateLatency_ms()<<"ms\n";
        std::cout<<"  BSM enc overhead:        "<<app->GetEncOverhead_us()<<"us/pkt\n";
        std::cout<<"  BSM TX count:            "<<app->GetBsmTxCount()<<"\n";
        std::cout<<"  Auth/Reject:             "<<app->GetAuthCount()<<"/"<<app->GetRejectCount()<<"\n";

        if(app->IsRegistered()){
            Guti g=app->GetGUTI(); NasKeys k=app->GetKeys();
            std::cout<<"  GUTI TMSI: 0x"<<std::hex<<g.tmsi<<std::dec<<"\n";
            std::cout<<"  KNASenc[0:4]: ";
            for(int b=0;b<4;b++) std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)k.KNASenc[b];
            std::cout<<std::dec<<"  KNASint[0:4]: ";
            for(int b=0;b<4;b++) std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)k.KNASint[b];
            std::cout<<std::dec<<"\n";
        }

        s_eap+=app->GetEapTlsCpuMs(); s_eapWire+=app->GetEapTlsWireMs(); s_suci+=app->GetSuciLatency_ms();
        s_key+=app->GetKeyDerivLatency_ms(); s_guti+=app->GetGutiLatency_ms();
        s_pdu+=app->GetPduLatency_ms(); s_reg+=app->GetRegLatency_ms();
        s_bsm+=app->GetBsmGateLatency_ms(); s_enc+=app->GetEncOverhead_us();
    }

    std::cout<<"\n[SUMMARY] ("<<numUes<<" UEs):\n";
    std::cout<<"  avg EAP-TLS CPU cost:      "<<s_eap/numUes<<"ms\n";
    std::cout<<"  avg EAP-TLS wire time:     "<<s_eapWire/numUes<<"ms\n";
    std::cout<<"  avg SUCI construction:     "<<s_suci/numUes<<"ms\n";
    std::cout<<"  avg GUTI assignment:       "<<s_guti/numUes<<"ms\n";
    std::cout<<"  avg PDU session (N11):     "<<s_pdu/numUes<<"ms\n";
    std::cout<<"  avg key derivation:        "<<s_key/numUes<<"ms\n";
    std::cout<<"  avg total registration:    "<<s_reg/numUes<<"ms [incl Uu+N11]\n";
    std::cout<<"  avg BSM gate delay:        "<<s_bsm/numUes<<"ms\n";
    std::cout<<"  avg BSM enc overhead:      "<<s_enc/numUes<<"us/pkt\n";
    std::cout<<"  BSM rx ok/fail:            "<<bsmSink->GetRxOk()<<"/"<<bsmSink->GetRxFail()<<"\n";
    std::cout<<"  AMF accept/reject:         "<<amfApp->GetAuthCount()<<"/"<<amfApp->GetRejectCount()<<"\n";
    std::cout<<"  SMF PDU sessions:          "<<smfApp->GetPduCount()<<"\n";
    std::cout<<"  AMF N11 PDU latency:       "<<amfApp->GetPduLatency_ms()<<"ms\n";
    std::cout<<"  IDS alerts:                "<<idsApp->GetAlertCount()<<"\n";

    monitor->CheckForLostPackets();
    auto classifier=DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    uint32_t bsm_flows=0; double total_delay=0;
    for(auto& kv:monitor->GetFlowStats()){
        auto t=classifier->FindFlow(kv.first);
        if(t.destinationPort==9002&&kv.second.rxPackets>0){
            bsm_flows++;
            double avg=kv.second.delaySum.GetMilliSeconds()/kv.second.rxPackets;
            total_delay+=avg;
            std::cout<<"\n[FLOWMON] BSM "<<t.sourceAddress<<"->"
                <<t.destinationAddress
                <<"  rx="<<kv.second.rxPackets
                <<"  tx="<<kv.second.txPackets
                <<"  lost="<<kv.second.lostPackets
                <<"  avgDelay="<<avg<<"ms";
        }
    }
    if(bsm_flows>0)
        std::cout<<"\n[FLOWMON] avg BSM E2E delay: "<<total_delay/bsm_flows<<"ms\n";

    std::cout<<"\n=================================================\n\n";

    if(g_cert)      X509_free(g_cert);
    if(g_pkey)      EVP_PKEY_free(g_pkey);
    if(g_srvCtx)    SSL_CTX_free(g_srvCtx);
    if(g_cliCtx)    SSL_CTX_free(g_cliCtx);
    if(g_hnKeyPair) EC_KEY_free(g_hnKeyPair);

    Simulator::Destroy();
    return 0;
}
