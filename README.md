# V2N 5G Registration: Classical vs Post-Quantum EAP-TLS (ns-3)

An ns-3 simulation of a vehicle-to-network (V2N) 5G UE registration with AMF, SMF and PDU session setup over an NR radio link. It compares the cost of EAP-TLS authentication across classical and post-quantum cryptography configurations.

## Configurations compared
| Label | Signature | Key exchange |
|---|---|---|
| classical | RSA | ECDHE |
| kem-only | RSA | ML-KEM-768 |
| hybrid-pqc | ML-DSA-44 | X25519MLKEM768 |
| pure-pqc | ML-DSA-44 | ML-KEM-768 |

## Files
- `v2n-ue-registration.cc` – the ns-3 simulation (SUCI/GUTI, key derivation chain, EAP-TLS flights, PDU session, encrypted BSMs)
- `run_sweep.sh` – runs every configuration over several trials and records handshake bytes, message count and registration latency
- `run_scale_sweep.sh` – scalability sweep over 1 to 50 UEs per configuration
- `scale_summary.csv` – results from the scalability sweep

## Run
Place `v2n-ue-registration.cc` in your ns-3 `scratch/` directory (with the 5G-LENA NR module), then from the ns-3 root:
```bash
./run_sweep.sh
./run_scale_sweep.sh
```
Both scripts accept environment overrides (for example `TRIALS=10`, `UE_COUNTS="1 10 50"`), documented at the top of each script.
