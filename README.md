# V2N 5G Registration with Post-Quantum EAP-TLS (ns-3 + 5G-LENA)

`v2n-ue-registration` is an ns-3 scratch program that simulates vehicles (UEs) registering
with a 5G core over an NR radio link, using **EAP-TLS mutual authentication** as the primary
authentication, with selectable **classical, hybrid and post-quantum** key exchange and
certificate signatures. It measures what the cryptography costs in bytes, latency and
AMF load as the number of UEs grows.

This README documents the program, how to run it, every problem we hit and how it was
solved, the results so far, and what is still open.

---

## 0. Project background and testbed

### Research question

How much does it cost, in bytes, latency and AMF load, for a vehicle (V2N) to register with
a 5G network when the primary authentication is **EAP-TLS**, and how does that cost change
when the TLS handshake uses **post-quantum** (PQC) key exchange and certificates? The
simulation exists to produce measured numbers for a paper on that question.

### The testbed

Everything runs in one ns-3 program, `v2n-ue-registration`, built on **ns-3.39** with the
**5G-LENA** NR module (`contrib/nr`) and **OpenSSL 3.5** for real cryptography.

```
 UE 0..N-1 --(Uu NR, n78 3.5 GHz)--> gNB --(S1/GTP)--> EPC/PGW --(point-to-point)--> remoteHost
 (vehicles)                                                                     AMF  :9000
                                                                                SMF  :9010 (N11 reply :9011)
                                                                                BSM sink :9002
                                                                                IDS      :9003
```

- **Radio and core:** 5G-LENA NR (numerology 1, 20 MHz, UMa line-of-sight, ideal beamforming)
  and the NR point-to-point EPC. This is a PHY/MAC-modeled link, not an IP-over-UDP shortcut.
- **AMF, SMF, BSM sink, IDS** are applications written for this project and run on the remote
  host. The UEs never talk to each other, so the topology is V2N only.
- **Real crypto:** SUCI uses ECIES (ECDH P-256 + HKDF + AES-CTR + HMAC, 87 B). The EAP-TLS
  handshake is a genuine TLS 1.3 handshake run through OpenSSL memory BIOs, so the byte counts
  per flight come from the actual handshake (`BIO_number_written` deltas), not from a table.
- **Security model:**
  1. The handshake is bound to the registration: a UE is only registered after the AMF sends
     EAP-Success.
  2. Both sides export the **MSK** (`SSL_export_keying_material`, label
     `"client EAP encryption"`, 64 bytes) and derive the key chain
     KAUSF = MSK[0:32] -> KSEAF -> KAMF -> KNASenc / KNASint. UE and AMF derive independently, and
     matching keys in the logs are the evidence that both ran the same handshake.
  3. TLS flights travel as **EAP-TLS packets (RFC 3748 / RFC 5216)** inside NAS messages, with the
     L/M/S flags and fragmentation. The AMF de-conceals the SUCI with the home-network private key.
  4. Mutual authentication is real (client certificate and server certificate).
- **Where simulated time comes from:** ns-3 executes every event in zero simulated time. To make
  crypto cost count, each OpenSSL call is timed with a wall clock (`CLOCK_MONOTONIC`) and the
  measured cost is injected with `Simulator::Schedule(NanoSeconds(cost), ...)`. The ns-3 manual
  (section 2.1) describes exactly this technique for computation-heavy events. An optional AMF
  worker-pool model (`--amfServers`) queues handshakes FIFO so server load shows up as delay.
- **Realtime mode:** `--realtime=1` uses ns-3's best-effort real-time scheduler to pace the
  simulation to the wall clock. It does not change the simulated results (see section 3).

### How the build was set up

- **OpenSSL 3.5 in isolation.** The system OpenSSL is 1.1.1f, which has no ML-KEM or ML-DSA.
  OpenSSL 3.5 was built under `~/openssl-3.5` so the system is untouched.
- **Custom `CMakeLists.txt`** in `scratch/v2n-ue-registration/` finds that exact OpenSSL with
  `find_path` / `find_library` and `NO_DEFAULT_PATH`, creates imported targets, and sets an rpath
  so the binary loads `libssl.so.3` from `~/openssl-3.5/lib64`. Plain `find_package(OpenSSL)` was
  tried first and silently picked the system library. The build target is named
  `scratch_v2n-ue-registration_v2n-ue-registration` (not the bare program name).
- The configure step prints three lines starting `v2n-ue-registration: OpenSSL ...`. Check they
  point at `~/openssl-3.5` and not `/usr/lib`.

### What was built, in order

1. Got the transferred ns-3 project to build and run (stale CMake cache, missing SQLite header,
   link-permission problem, see section 9).
2. The five security-model fixes listed above (handshake bound to registration, per-flight byte
   counts, simulated-time vs CPU-time separation, EAP-fragmented NAS transport, real SUCI
   de-concealment).
3. Converted to real EAP-TLS primary authentication, with realtime pacing, and checked it
   against RFC 5216 (section 10 lists the gaps that remain).
4. Post-quantum: ML-DSA-44 certificates, ML-KEM-768 key exchange (pure, and hybrid
   X25519MLKEM768 for comparison), with a log line that states which group and which signature
   algorithm were actually negotiated: `[PQC CONFIRMED]` or `[CLASSICAL ONLY]`.
5. EAP-TLS fragment size set to 1500 (section 10).
6. Sweep scripts and CSV output: bytes, message count and latency per configuration, including a
   Diffie-Hellman vs KEM comparison (section 4 and 6).
7. UE-count scalability experiments (section 4, 6 and 7).
8. Supporting material: a 13-slide progress presentation for the supervisor, a flow figure, and a
   related-work and novelty review (section 11).

---

## 1. What the simulation does

Each UE goes through a registration flow:

1. **SUCI construction.** The UE conceals its SUPI with the home network's P-256 public
   key (87 B SUCI). The AMF de-conceals it with the private key.
2. **EAP-TLS primary authentication.** AMF and UE run a real TLS 1.3 handshake (OpenSSL 3.5)
   carried in EAP messages over the simulated NR link. Both sides present certificates
   (mutual authentication). Flights are fragmented/reassembled and every handshake step is
   timed.
3. **Key derivation.** KAUSF is derived from the EAP-TLS MSK, then the KSEAF/KAMF/NAS key chain
   (KNASenc, KNASint).
4. **GUTI assignment** by the AMF.
5. **PDU session** requested from the SMF over N11.
6. **BSM traffic.** After registration the UE sends periodic encrypted basic safety messages
   to a BSM sink. An IDS node watches the traffic.

Radio: Uu NR, n78 at 3.5 GHz, 20 MHz, numerology 1, UMa line-of-sight channel, 1 gNB by
default. Nodes: UEs, gNB, and one remote host that runs the AMF (port 9000), SMF (9010),
N11 response (9011), BSM sink (9002) and IDS (9003).

### Security configurations

| Label (in sweeps) | `--sigAlg` | `--kemGroup` | Meaning |
|---|---|---|---|
| classical | `RSA` | `ECDHE` | RSA certificates, X25519 key exchange (baseline) |
| kem-only | `RSA` | `MLKEM768` | Only the key exchange is post-quantum |
| hybrid-pqc | `ML-DSA-44` | `X25519MLKEM768` | PQ signatures, hybrid classical+PQ key exchange |
| pure-pqc | `ML-DSA-44` | `MLKEM768` | Fully post-quantum |

`ECDHE` is mapped to X25519 in the code. `kem-only` vs `classical` isolates the key-exchange
change (both use RSA certificates); `pure-pqc` vs `classical` changes both at once.
`hybrid-pqc` is only in `run_sweep.sh`, not in the scale sweep.

---

## 2. Files

| File | Purpose |
|---|---|
| `v2n-ue-registration.cc` | The simulation (goes in `~/ns-3-dev/scratch/v2n-ue-registration/`) |
| `run_scale_sweep.sh` | Scalability sweep: 3 configs x UE counts x trials, writes `scale_summary.csv` |
| `run_sweep.sh` | Small comparison of 4 configs (uses the program's defaults, so 10 UEs now), writes `sweep_summary.csv` and `sweep_results.csv` |
| `scratch/v2n-ue-registration/CMakeLists.txt` | Finds OpenSSL 3.5 in `~/openssl-3.5` with `NO_DEFAULT_PATH`, links it, sets the rpath (section 0) |
| `~/openssl-3.5` | Isolated OpenSSL 3.5 build with ML-KEM and ML-DSA. The system OpenSSL (1.1.1f) is left alone |
| `sweep_summary.csv`, `sweep_results.csv`, `scale_summary.csv` | Result tables written by the two sweep scripts |
| `5G V2N EAP-TLS Progress Presentation.pptx` | 13-slide progress deck for the supervisor |

Environment used: ns-3.39, 5G-LENA (`contrib/nr`), OpenSSL 3.5 (`~/openssl-3.5`),
Intel Core Ultra 9 285K (24 cores, hybrid P/E design).

---

## 3. Build and run

```bash
cd ~/ns-3-dev
cp <your download>/v2n-ue-registration.cc scratch/v2n-ue-registration/
./ns3 build v2n-ue-registration 2>&1 | grep -E "error|Finished"
```

The build prints many `-Wdeprecated-declarations` (OpenSSL 3.0 `EC_KEY_*`) and `-Wreorder`
warnings. They are harmless. `ninja: no work to do` means it is already up to date, and
`./ns3 build` only compiles, it never runs the simulation.

Run with the program defaults (10 UEs, realtime, about 25 s):

```bash
./ns3 run v2n-ue-registration
```

Recommended settings for larger runs (50 UEs on one gNB):

```bash
./ns3 run "v2n-ue-registration --realtime=0 --attachSpacingMs=10 --numUes=50 \
  --ueStagger=0.005 --ueSpacing=2 --amfServers=4 --simTime=14"
```

To see only the summary of a large run:

```bash
./ns3 run "v2n-ue-registration ... " 2>&1 | sed -n '/\[SUMMARY\]/,/IDS alerts/p'
```

### Command-line options

| Option | Default | Description |
|---|---|---|
| `--numUes` | 10 | Number of vehicle UEs (was 2 originally) |
| `--numGnbs` | 1 | Number of gNBs. UEs are split evenly and grouped around their own gNB |
| `--gnbSpacing` | 1000 | Metres between consecutive gNBs |
| `--simTime` | 25 | Simulation length in simulated seconds |
| `--sigAlg` | ML-DSA-44 | `RSA`, `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` |
| `--kemGroup` | MLKEM768 | `ECDHE`, `MLKEM768`, `X25519MLKEM768` |
| `--realtime` | 1 | 1 = paced to the wall clock, 0 = as fast as possible |
| `--attachSpacingMs` | 0 | Ms between UE radio attaches. 0 = all attach at t=0. See section 5 |
| `--ueStagger` | 0.1 | Seconds between UE start times. See section 5 |
| `--ueSpacing` | 20 | Metres between consecutive UEs along x |
| `--amfServers` | 0 | AMF crypto CPU workers. 0 = unlimited (no queueing). N = jobs queue FIFO on N workers |

Any ns-3 attribute can also be set on the command line, for example
`--ns3::LteEnbRrc::SrsPeriodicity=320`. `./ns3 run "v2n-ue-registration --PrintAttributes=ns3::LteEnbRrc"`
lists a class's attributes. An unrecognised argument makes the program print its help text
instead of running.

### Reading the output

Each UE prints a block (`registered`, EAP-TLS result, negotiated group, certificate algorithm,
timings), followed by `[SUMMARY]` (averages, `AMF accept/reject`, SMF sessions, IDS alerts)
and `[FLOWMON]` (BSM delivery per UE).

**Simulated vs measured time.** This matters for any result you report:

- Lines marked `(sim)` or `[sim E2E ...]`, including EAP-TLS wire time, total registration
  and BSM delay, are **simulated time** (the model's clock).
- `EAP-TLS CPU cost` and the other crypto costs (SUCI, key derivation) are **measured**:
  the real wall-clock time of the OpenSSL calls on your machine, injected into the simulation
  as processing delay.
- `--realtime=0` finishes in seconds. `--realtime=1` makes the run last as long as the
  simulated time. **The simulated results are identical in both modes**, and realtime does not
  make the results more accurate. It is useful only for live demos or emulation. It runs in
  best-effort mode, so if the machine falls behind it catches up late and does not abort.

---

## 4. Running the sweeps

```bash
bash run_scale_sweep.sh                       # defaults: UE counts 1 2 5 10 20 50, 3 trials
UE_COUNTS="1 10 50" TRIALS=10 bash run_scale_sweep.sh
taskset -c 2 bash run_scale_sweep.sh          # pinned to one core (see section 6)
```

Settings (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `UE_COUNTS` | `1 2 5 10 20 50` | UE counts to test |
| `TRIALS` | 3 | Repeats per point |
| `STAGGER` | 0.005 | Seconds between UE start times, same for every count so the curve is comparable |
| `ATTACH_MS` | auto | 0 for 20 UEs or fewer, 10 above that. Do not use 1 or 5 |
| `SPACING` | 2 | Metres between UEs |
| `AMF_SERVERS` | 4 | AMF crypto workers |
| `GNBS` | 1 | Number of gNBs. `auto` spreads UEs over `ceil(n/UES_PER_GNB)` gNBs |
| `UES_PER_GNB` | 20 | Used only when `GNBS=auto` |
| `REALTIME` | 0 | Passed as `--realtime=$REALTIME` if that line is edited to use it (see note below) |
| `OUT` | `scale_summary.csv` | Output file |

Note: in the author's copy the run line contains `--realtime=1` directly. To switch modes
from the command line, change that part of the line to `--realtime=$REALTIME`.

Output columns in `scale_summary.csv`: `config, num_ues, num_gnbs, trial, stagger_s,
spacing_m, amf_servers, registered, rejected, total_bytes, bytes_per_ue, msg_count,
lat_min_ms, lat_avg_ms, lat_p95_ms, lat_max_ms, amf_tls_cpu_ms, run_ok`.
`run_ok=0` means the program crashed and never printed its summary.

Integrity check after a sweep (prints only mismatches):

```bash
awk -F, 'NR>1 && $2!=$8 {print "MISMATCH:", $0}' scale_summary.csv; echo "check done"
```

---

## 5. Problems found and how they were solved

This section is the troubleshooting history. The original program crashed on startup, and
scaling to 50 UEs took several rounds of testing. Each item says what was verified by running
it and what is still only an explanation.

### 5.1 Crash at t=0: `initialBandwidthWithOverhead == 0`

- **Symptom:** `aborted ... dlBandwidthInRBNum = 6, m_subcarrierSpacing = 0` in `nr-ue-phy.cc`.
- **Cause:** the UE PHY was never given a numerology, so its subcarrier spacing stayed 0.
  Only the gNB PHY had `Numerology` set.
- **Fix:** after `InstallUeDevice`, call `SetNumerology(numerology)` on every UE PHY.
- **Pitfall:** `NrUePhy` has no `Numerology` attribute. `SetUePhyAttribute("Numerology", ...)`
  aborts with `Invalid attribute set (Numerology) on ns3::NrUePhy`. Use the method.
- **Status:** verified working. I could not see the earlier working version of the code, so
  this is a fix for the cause, not a restoration of the old text.

### 5.2 Staggered attach crashes: `unexpected event in state IDLE_WAIT_MIB`

- **Symptom:** with `--attachSpacingMs=1` or `5`, abort at 0.018535713 s in `lte-ue-rrc.cc`.
- **Observations:** the abort happens at the same instant for both spacings. Spacings of
  10 ms and above did not trigger it in later tests (including at 50 UEs).
- **Workaround:** use `--attachSpacingMs=0` or 10 or more. The root cause was not identified.

### 5.3 UEs above about 10 never register (0/12, 0/20, 13/30, 9/40)

- **Symptom:** the program runs but `AMF accept/reject` is far below the UE count. Every UE
  prints `Registration Request sent`, yet the AMF logs none received.
- **What was ruled out:** all UEs did reach the radio-connected state. At 50 UEs the log showed
  `50 CONNECTED_NORMALLY`, so the radio attach was not the problem.
- **Cause:** with `--ueStagger=0` or `0.001`, many UEs send their first packet at nearly the
  same instant and most of those packets never reach the AMF.
- **Fix:** a larger stagger. At 50 UEs: 1 ms gives only 13 registered, while 5, 10, 20 and
  100 ms all give 50/50. 5 ms is used as the default. The cause of the loss at the NR layer
  was not isolated.
- **Never use `--ueStagger=0`:** more than 10 UEs then never register.

### 5.4 Crash at the 41st UE: `could not find RNTI = 0`

- **Symptom:** `NS_ASSERT ... nr-rrc-protocol-ideal.cc line 254` at 50 UEs, at the moment the
  41st UE attaches, whatever the attach spacing (10, 20 or 50 ms).
- **Cause:** the cell can only assign SRS slots to `ns3::LteEnbRrc::SrsPeriodicity` UEs, and
  its default is 40.
- **Fix:** `Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity", 320)`, applied by the program
  only when `numUes > 40`, so smaller runs are unchanged. Allowed values are 2, 5, 10, 20, 40,
  80, 160 and 320 (0 is rejected). With 320, 50 UEs on a single gNB register 50/50.
- **Status:** the crash disappeared when the value was raised. A second gNB is therefore not
  required, but `--numGnbs` was added anyway (default 1).

### 5.5 Other changes

- Default `numUes` changed from 2 to 10.
- `run_scale_sweep.sh` no longer hardcodes `--attachSpacingMs=5`. It now uses an attach
  spacing per UE count, one fixed stagger, and records `num_gnbs` and the stagger used.
- One uploaded copy of `v2n-ue-registration.cc` had terminal output pasted into the middle
  of the source (inside the `g_sigAlg` line). It would not compile. If a build fails with
  strange errors near line 463, check for that.

### Quick reference: symptom to cause

| Symptom | Likely cause | Fix |
|---|---|---|
| `initialBandwidthWithOverhead == 0` at t=0 | UE PHY has no numerology | `SetNumerology` on UE PHYs |
| `Invalid attribute set (Numerology) on ns3::NrUePhy` | Used an attribute instead of the method | Use `SetNumerology()` |
| `unexpected event in state IDLE_WAIT_MIB` | `--attachSpacingMs` of 1 or 5 | Use 0 or 10+ |
| `accept/reject` far below UE count, no crash | `--ueStagger` too small | Use 0.005 or more |
| `could not find RNTI = 0` at the 41st UE | SRS slots exhausted (default 40) | `SrsPeriodicity=320` (automatic above 40 UEs) |
| Program prints its help text | An unrecognised option (for example `--numGnbs` on an old build) | Rebuild, or drop the option |
| `illecit SRS periodicity value 0` | 0 is not an allowed value | Use 320 |

---

## 6. Results so far

Settings: 1 gNB, `--amfServers=4`, `--ueSpacing=2`, 3 trials, stagger 0.005 s for every count,
attach 0 ms up to 20 UEs and 10 ms for 50. These are from the realtime sweep. All 54 runs
completed, every UE registered, nothing was rejected, and `run_ok=1` on every row.

### Bytes per UE (identical across trials and UE counts)

| Config | EAP-TLS bytes per UE | Messages per UE |
|---|---|---|
| classical | 4,512 | 4 |
| kem-only | 6,712 | 4 |
| pure-pqc | 23,840 | 4 |

pure-pqc is about 5.3x classical in bytes. The key exchange alone (kem-only vs classical)
adds about 2.2 kB per UE. The remaining 17 kB or so comes from the ML-DSA certificates
and signatures.

### Average registration latency, simulated (ms)

| UEs | classical | kem-only | pure-pqc |
|---|---|---|---|
| 1 | 26.5 | 29.5 | 30.8 |
| 2 | 26.4 | 29.8 | 30.2 |
| 5 | 26.8 | 29.1 | 30.4 |
| 10 | 25.6 | 29.2 | 29.9 |
| 20 | 25.9 | 29.3 | 30.4 |
| 50 | 26.2 | 29.8 | 30.4 |

The fast-mode sweep gave the same latencies, which confirms realtime does not change them.

### What the results show, and what they do not

- **Post-quantum cost** is about 5x more bytes and about 4 ms more registration latency
  (30 vs 26 ms), constant from 1 to 50 UEs in this setup.
- **Latency is flat with UE count here because the 5 ms stagger spreads registrations out.**
  Each handshake takes about 30 ms, so they mostly finish before the next UE starts and the
  AMF does not queue. This is **not** a measurement of behaviour under a tight burst.
- **The burst case.** An earlier fast sweep used a 1 ms stagger up to 20 UEs. There pure-pqc
  rose from 30 ms (1 UE) to 35 ms (10 UEs) and 66 ms (20 UEs), while classical stayed near
  26 ms. Its 50-UE row used a different stagger, so it was not comparable, which is why the
  stagger was fixed at 0.005 for all counts. A true burst test needs a stagger of 1 ms or
  less, but that registers only 13 of 50 UEs at 50 UEs (section 5.3). Always state the stagger
  with any latency result.

### Earlier 4-configuration comparison (`run_sweep.sh`, 2 UEs, 5 trials)

This was the first CSV comparison, run before the scale sweep. Totals are summed over both UEs
and all four EAP-TLS flights each (8 messages per run, every time).

| Config | Total bytes (2 UEs) | Per UE | Avg registration latency (ms, simulated) |
|---|---|---|---|
| classical (RSA + ECDHE) | 9,024 | 4,512 | about 26.0 |
| kem-only (RSA + MLKEM768) | 13,424 | 6,712 | about 28.6 |
| hybrid-pqc (ML-DSA-44 + X25519MLKEM768) | 47,808 | 23,904 | about 30.1 |
| pure-pqc (ML-DSA-44 + MLKEM768) | 47,680 | 23,840 | about 29.6 to 29.9 |

- Per-flight sizes (one UE): classical 290 / 1299 / 1069 / 1854 B; pure-pqc
  1434 / 7719 / 6433 / 8254 B. The hybrid group adds 64 B per UE over pure ML-KEM (32 B of X25519
  in each direction).
- The pasted pure-pqc data was missing trial 5, so its latency is a range. The latency
  differences between the PQC rows are within run-to-run noise at 5 trials; only the gap to
  classical is clear.
- **Do not compare PQC latency with runs made before realtime pacing was added.** An early
  comparison like that was wrong and was withdrawn. A suggestion that fewer fragments lower
  latency was also not supported by the data.
- Single runs are unreliable because the CPU cost is a wall-clock measurement. Use many trials
  (10 to 20) for any number that goes into the paper.

### AMF CPU cost: pin the process before reporting it

`amf_tls_cpu_ms` is measured wall-clock time of `SSL_do_handshake()` (`CLOCK_MONOTONIC`), so it
depends on the core the process runs on.

| Test (classical, 20 UEs, summed AMF CPU) | Result |
|---|---|
| Unpinned, 8 runs | 24.3 ms in every run |
| Pinned to CPU 2, 8 runs | 12.1 ms in every run |
| pure-pqc pinned to CPU 2, 8 runs | 11.4 to 14.0 ms (average about 12.6) |

- The Core Ultra 9 285K mixes fast and slow cores. The same work costs exactly twice as
  much on one kind as on the other, which explains the 12 vs 24 ms jumps between trials
  in the sweep.
- **Classical is not more expensive than pure-pqc on the AMF** when both run on the same core
  (12.1 vs about 12.6 ms). The apparent difference in the unpinned sweep (61 vs 45 ms at
  50 UEs) came from core placement.
- **To collect the AMF CPU column, pin the sweep to one performance core.** Check which CPUs
  they are with `cat /sys/devices/cpu_core/cpus` and then run:

  ```bash
  taskset -c 2 bash run_scale_sweep.sh
  ```

  The pinned sweep has not been run yet, so the AMF CPU column in the results above should
  not be reported.
- ML-DSA timing varies from run to run (probably because signing retries a variable number
  of times) while RSA is constant. This is an explanation, not something measured directly.

---

## 7. Limits that have been verified

| Setup | Result |
|---|---|
| 1 to 10 UEs, attach 0, stagger 0.001 | All register |
| 12 and 20 UEs, attach 0, stagger 0.001 to 0.1 | All register |
| 12 or more UEs, `--ueStagger=0` | 0 register (never use) |
| 30 / 40 UEs, attach 0, stagger 0.001 | 13/30 and 9/40 register |
| 50 UEs, attach 10 ms, stagger 0.001 | 13/50 register, no crash |
| 50 UEs, attach 10 ms, stagger 0.005 / 0.01 / 0.02 / 0.1 | **50/50 register** |
| 50 UEs without `SrsPeriodicity=320` | Crash at the 41st UE |
| 100 UEs | **Not tested** |

---

## 8. Open items

1. **Pinned sweep.** Run `taskset -c 2 bash run_scale_sweep.sh` (on a performance core) and
   use that run for the AMF CPU column. Use more trials (`TRIALS=10`) for ML-DSA.
2. **100 UEs and beyond.** Untested. `SrsPeriodicity` cannot go above 320, and the simulated
   time and run time grow. Test 100 UEs on their own first:
   `--numUes=100 --attachSpacingMs=10 --ueStagger=0.005 --simTime=20`.
3. **Burst behaviour.** Measuring AMF queueing needs a stagger of 1 ms or less at high UE
   counts, which currently loses most registrations (section 5.3). Understanding why those
   packets are dropped at the NR layer would allow a true burst test.
4. **Attach spacing below 10 ms.** The `IDLE_WAIT_MIB` abort at 1 and 5 ms has no identified
   root cause.
5. **hybrid-pqc** is only covered by `run_sweep.sh`. Add it to the scale sweep if hybrid
   results are needed.
6. **For the paper:** report latencies as simulated time, report crypto cost as measured on
   the stated CPU with the process pinned, and state the stagger, attach spacing and
   `--amfServers` used.
7. **Packet loss.** Not built. Needs per-fragment ACK and a retransmission timer first
   (sections 10.2 and 10.4), then a seeded `--lossRate`, then a loss sweep per configuration.
8. **Fragment-size sweep.** Add `--eapFragSize` and a fragment-count column, then test sizes
   such as 500, 1000, 1400, 1500 and 4000 (section 10.1). Check whether IP fragments the
   1500-byte payloads on the radio and EPC links.
9. **More certificate types.** ML-DSA-65 and ML-DSA-87 only need a flag. SLH-DSA needs code.
   Falcon / FN-DSA needs an external provider (section 10.3). A classical ffdhe2048 key
   exchange row could be added for the DH-vs-KEM comparison.
10. **Independent check of PQC negotiation** with a Wireshark capture.
11. **Code version control.** Keep one authoritative `v2n-ue-registration.cc` that contains all
    the fixes in section 5 (see the warning in section 9.2), and record its checksum with each
    result set.
12. **Real RRC** is not available in this NR module (section 9.2). If it is needed, the module
    would have to be changed, which affects every simulation that uses it.

---

## 9. Build, tooling and run problems (full history)

### 9.1 Environment and tooling

| Symptom | Cause | Fix |
|---|---|---|
| CMake configure fails after files were moved | Stale `cmake-cache` | `rm -rf cmake-cache build`, then `./ns3 configure --enable-examples --enable-tests` |
| Missing SQLite header | Dependency not installed | `sudo apt install libsqlite3-dev` |
| `Permission denied` on a `//ns3...` path while linking | An example inside the tree used a bad output path | Moved the example out of the tree |
| Peer-certificate verification still failed with the "accept all" callback | The error code was not cleared | Inside the verify callback: `X509_STORE_CTX_set_error(ctx, X509_V_OK); return 1;` |
| Build picked the system OpenSSL (1.1.1f) | `find_package(OpenSSL)` caches the first OpenSSL it finds anywhere | Custom `find_path` / `find_library` with `NO_DEFAULT_PATH` (section 0) |
| `Can not find target to add properties to: v2n-ue-registration` | `build_exec` names the target `scratch_<folder>_<name>` | Use `scratch_v2n-ue-registration_v2n-ue-registration` in `set_target_properties` |
| `Cannot find source file v2n-ue-registration.cc` | The `.cc` was not in `scratch/v2n-ue-registration/` | Copy it there, then check with `grep -c` and `wc -c` |
| `libssl.so.3: cannot open shared object file` when running the standalone `openssl` tool | Loader does not look in `~/openssl-3.5/lib64` | `LD_LIBRARY_PATH=~/openssl-3.5/lib64`. The simulation binary has an rpath and does not need it |
| Null `Ptr` assert with `--simTime=5` | A BSM was scheduled after its socket was closed | Null guards in `SendBsm` and `TransmitBsm` |
| N11 latency inflated after the AMF queue was added | The clock started before the job waited for a CPU worker | Start the N11 clock inside `SendPduSessionRequest` |
| Downloaded files were stale or truncated | Browser saved duplicates such as `file (1).cc`; one `CMakeLists.txt` was 1566 B instead of 3175 B | Check with `grep -c` and `wc -c` after every copy |
| `Permission denied` running a `.sh` script | Downloads lose the execute bit | `chmod +x` after each copy |
| Bash syntax error running `./run_sweep(2).sh` | Parentheses in the file name | Rename the file |
| `bash: /ns3: No such file or directory` | Typed `/ns3` instead of `./ns3` | Use `./ns3` from `~/ns-3-dev` |
| AMF log prints `KNASenc[0:4]=5413ebd` while the UE summary shows `54013ebd` | The AMF log line drops leading zeros (cosmetic) | Not fixed. The keys do match |

### 9.2 The failed 100-UE sweep and the attempts that followed

**Warning about code versions.** The `v2n-ue-registration.cc` that was last handed over in that
debugging session is an older copy. It does **not** contain the fixes described in sections 3
and 5 (`SetNumerology` on UE PHYs, `--numGnbs`, `SrsPeriodicity`, `--attachSpacingMs`, default of
10 UEs). Use the version of the file that does. If `--numGnbs` or `--attachSpacingMs` are
unrecognised, the file is the old one.

What happened:

1. `UE_COUNTS="100" TRIALS=5 ./run_scale_sweep.sh` produced 15 rows that all had `registered=0`
   and `run_ok=0`. Running one case by hand showed the abort `could not find RNTI = 0`
   (`nr-rrc-protocol-ideal.cc`, line 254) at 0.0185 s. Section 5.4 gives the cause that matched:
   the cell's SRS slots (default 40) run out.
2. A first explanation, that simultaneous random access by many UEs collided, was a guess and
   was not supported by later tests.
3. At 20 and 30 UEs the program did not crash but `AMF accept/reject` was `0/0`. This matches
   section 5.3 (too small a stagger), not a radio fault.
4. **Real RRC is not available in this NR module.** `--idealRrc` / `UseIdealRrc` on `NrHelper`
   aborts with `Attribute name=UseIdealRrc does not exist`. In `contrib/nr/helper/nr-helper.cc`
   ideal RRC is hardcoded (`bool useIdealRrc = true;`) and the module contains only
   `nr-rrc-protocol-ideal.*`. Switching would mean changing the module itself.
5. A first attempt at staggering the attach with `Simulator::Schedule` aborted with
   `initialBandwidthWithOverhead == 0` at t=0. That is the same message as section 5.1, which
   explains it: the UE PHY needs `SetNumerology` before the attach.
6. The 1000-UE question: no run was made. A guess of 10 to 60 minutes per run was not measured.
   Time 50 and 100 UEs first and extrapolate.

The practical rule that came out of this: **print the full error before theorising.** A filter
such as `grep NS_ASSERT` hides `NS_FATAL` messages and makes every failure look the same.

---

## 10. Protocol notes and design decisions

### 10.1 EAP-TLS fragment size and MTU

- `EAP_TLS_FRAG_MTU` is **1500**. It is the number of **TLS payload bytes per EAP fragment**, not
  a link MTU. Every fragment except the last carries exactly 1500 payload bytes.
- Each fragment adds 7 bytes of header (NAS byte, code, identifier, 2-byte length, type, flags),
  and the first fragment of a fragmented message adds 4 more (the total-length field), so a full
  first fragment is 1511 B and later full fragments are 1507 B.
- The only link MTU set explicitly in the code is 2500 on the PGW to remote-host point-to-point
  link. The radio and EPC links use the ns-3 defaults, so a 1500-byte payload plus UDP and IP
  headers may be fragmented again by IP. Whether this happens in a run has not been verified.
  A value near 1400 would keep each packet within 1500 bytes.
- Changing the fragment size changes the number of fragments, ceil(flight / size), and the total
  header overhead, but not correctness, because reassembly follows the M flag. The EAP length
  field is 16 bits, so a fragment must stay below about 65,000 B.
- `message_count` in the CSVs counts **flights** (4 per UE), not fragments. A fragment-size study
  would need a new fragment-count column and an `--eapFragSize` option (neither exists yet).

### 10.2 Compliance with RFC 5216 and what is missing

Implemented: the EAP header (code, identifier, length, type 13, flags), the L / M / S flags,
fragmentation and reassembly, EAP-Success / EAP-Failure as the gate for registration, and the
MSK export label `"client EAP encryption"`. For TLS 1.3 the relevant specification is RFC 9190,
which updates RFC 5216.

Not implemented (from reading the code, not from a conformance test):

- no **per-fragment acknowledgement** (an empty EAP-TLS response to each non-final fragment);
- no **retransmission timer** and no retry limit;
- the reassembler (`FeedEapFrag`) treats a cleared M flag as "complete" and does not check the
  received length against the total-length field;
- fragments of one flight are sent as an unacknowledged burst.

Consequence: if a fragment is lost, the handshake stalls or reassembles wrongly, so the current
code cannot be used to study packet loss. See 10.4.

### 10.3 Post-quantum choices

- **Key exchange:** pure ML-KEM-768 (`MLKEM768`). Hybrid `X25519MLKEM768` is kept only as a
  comparison row. The classical baseline is X25519 (`ECDHE`).
- **Certificates:** ML-DSA-44. `--sigAlg` also accepts ML-DSA-65 and ML-DSA-87. SLH-DSA
  (FIPS 205) is supported by OpenSSL 3.5 but is not wired in. Falcon / FN-DSA is **not** in
  OpenSSL's default provider, so it cannot be added without an external provider.
- **Why both a KEM and a signature algorithm:** the KEM protects the secrecy of the session key
  against a future quantum attacker (harvest now, decrypt later). The signature algorithm
  protects the authentication of the certificates. Using one does not cover the other.
- **DH vs KEM:** `classical` vs `kem-only` changes only the key exchange (both use RSA
  certificates), so the difference between those two rows is the cost of the KEM alone.
- **Confirming that PQC is really used:** the run prints `Negotiated group: ... [PQC CONFIRMED]`
  (or `[CLASSICAL ONLY]`) and the peer certificate algorithm, read from the finished TLS session.
  A Wireshark capture of the handshake would be an independent check (not done yet).

### 10.4 Artificial packet loss (design only, not implemented)

Planned approach: a seeded `RateErrorModel` on the radio link (and optionally the core link)
behind a `--lossRate` flag, plus the two missing protocol pieces from 10.2 (per-fragment ACK and
a retransmission timer with a retry limit, for example `--eapRto`). Without those, a lost fragment
only produces a failed registration and no latency number. Large PQC flights (about 6 fragments
each) have more packets to lose than classical ones (1 to 2), so the same loss rate should hurt
PQC more. That is a hypothesis to test, not a result. Output columns to add: loss rate,
retransmission count, registered or failed.

---

## 11. Related work and novelty (literature search, hedged)

A literature search was done to check what is new here. These are statements of **absence of
evidence found**, not proof. Re-check late-2026 preprints before submitting, and verify every
reference before citing it.

Closest prior work:

| Work | What it does | Difference from this project |
|---|---|---|
| Cheng et al., "Implementing EAP-TLS in free5GC for Non-SIM Device Connectivity", free5GC World Forum 2025 (DOI 10.1145/3733814.3765500) | EAP-TLS as 5G primary authentication on free5GC + UERANSIM, end-to-end latency | A testbed with no PHY/MAC model; RFC 5216 / TLS 1.2 era; latency injected per message; aggregate latency only. Camera-ready not read in full, so confirm before a hard contrast claim |
| Sabanci et al., PQC TLS for 5G NB-IoT (arXiv 2309.03338) | TLS 1.3 handshake in ns-3 over an NB-IoT model | Handshake sizes computed offline, no live crypto, not primary authentication, no NAS keys |
| Gharib and Afghah, SCC5G (arXiv 2308.10696) | PQC + PUF architecture evaluated in ns-3 | Not EAP-TLS or certificate-based; no SUCI / SIDF cost |
| Edris, Aiash and Loo, EAP-AKA' evaluation (*Array* 16, 100254, 2022) | NS-3 evaluation of EAP-AKA' vs 5G-AKA compute | Symmetric AKA, not certificate-based; compute cost plugged in |
| Basin et al., "A Formal Analysis of 5G Authentication", CCS 2018 (DOI 10.1145/3243734.3243846) and ProVerif studies of EAP-TLS 1.3 | Formal (symbolic) analysis | Formal, not empirical performance |

Claims to lead with (each phrased "to the best of our knowledge"):

1. EAP-TLS primary authentication measured with live cryptography inside a radio-aware
   (PHY/MAC-modeled) discrete-event simulator.
2. Wall-clock crypto cost measured and injected as scheduled delay so it consumes simulated time
   in a 5G authentication study. The technique itself is documented in the ns-3 manual, so the
   claim is its application here, not its invention.
3. Per-flight byte accounting of the fragmented handshake, with UE and AMF independently
   deriving matching KNASenc / KNASint from the exported MSK as evidence of a shared handshake,
   in a V2N registration scenario.

Also worth reporting on its own: server-side SUCI de-concealment cost, for which no comparable
published number was found.

Other references to read: RFC 3748, RFC 5216, RFC 9190, 3GPP TS 33.501 (primary
authentication, Annex B, Annex C), Sikeridis et al. NDSS 2020 (DOI 10.14722/ndss.2020.24203), and
Patriciello et al., "An E2E Simulator for 5G NR Networks" (SIMPAT 96, 101933, 2019).
