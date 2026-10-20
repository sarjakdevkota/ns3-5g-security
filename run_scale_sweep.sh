#!/usr/bin/env bash
# Scalability sweep: how does EAP-TLS registration cost grow with the number
# of UEs registering, for each certificate / key-exchange configuration?
#
# Output: scale_summary.csv — one row per (config, UE count, trial).
#
# Settings (override with env vars, e.g.  UE_COUNTS="1 10 50" TRIALS=5 ./run_scale_sweep.sh):
#   UE_COUNTS    UE counts to test.                               default: 1 2 5 10 20 50
#   TRIALS       repeats per point (CPU timing is noisy).         default: 3
#   STAGGER      seconds between UE start times. default: auto
#                auto = 0.001 for <=20 UEs, 0.005 above. Never 0 (all UEs
#                sending at one instant: >10 UEs never reach the AMF).
#                At 50 UEs: 1 ms registers only 13; 5, 10, 20, 100 ms all give 50/50.
#   SPACING      metres between UEs. Kept small so distance from  default: 2
#                the gNB isn't what drives per-UE latency.
#   AMF_SERVERS  AMF crypto CPU workers. 0 = unlimited (server    default: 4
#                crypto never queues, which flatters PQC at scale).
#
#   ATTACH_MS    ms between UE radio attaches. default: auto
#                auto = 0 (all at t=0) for <=20 UEs, 10 above. Do not use
#                1 or 5: aborts with "unexpected event in state IDLE_WAIT_MIB".
#                Above 40 UEs the program also sets SrsPeriodicity=320.
#   GNBS         number of gNBs. default: 1 (single cell; 50 UEs works).
#                Set GNBS=auto to spread UEs over ceil(n/UES_PER_GNB)
#                gNBs (UES_PER_GNB default 20), 1000 m apart.
#
# Uses --realtime=0 (reported byte counts / simulated delays are identical
# to realtime mode; only the program's own runtime differs).

set -u
NS3="${NS3:-./ns3}"
TARGET="v2n-ue-registration"
TRIALS="${TRIALS:-3}"
UE_COUNTS="${UE_COUNTS:-1 2 5 10 20 50}"
STAGGER="${STAGGER:-0.005}"
SPACING="${SPACING:-2}"
AMF_SERVERS="${AMF_SERVERS:-4}"
ATTACH_MS="${ATTACH_MS:-auto}"
UES_PER_GNB="${UES_PER_GNB:-20}"
GNBS="${GNBS:-1}"
REALTIME="${REALTIME:-0}"
OUT="${OUT:-scale_summary.csv}"

# label,sigAlg,kemGroup
CONFIGS=(
  "classical,RSA,ECDHE"
  "kem-only,RSA,MLKEM768"
  "pure-pqc,ML-DSA-44,MLKEM768"
)

echo "config,num_ues,num_gnbs,trial,stagger_s,spacing_m,amf_servers,registered,rejected,total_bytes,bytes_per_ue,msg_count,lat_min_ms,lat_avg_ms,lat_p95_ms,lat_max_ms,amf_tls_cpu_ms,run_ok" > "$OUT"

for cfg in "${CONFIGS[@]}"; do
  IFS=',' read -r label sigAlg kemGroup <<< "$cfg"
  echo "=== $label (sigAlg=$sigAlg kemGroup=$kemGroup) ==="

  for n in $UE_COUNTS; do
    # "auto": n<=20 keeps the settings already validated (attach at t=0, 1 ms
    # start stagger). Above 20 UEs a t=0 attach / 1 ms burst loses most
    # registrations, so use a 10 ms attach spacing and a 5 ms start stagger
    # (50 UEs on ONE gNB then register 50/50; >40 also needs SrsPeriodicity=320,
    # which the program sets itself).
    if [ "$STAGGER" = "auto" ]; then if [ "$n" -le 20 ]; then stag=0.001; else stag=0.005; fi; else stag=$STAGGER; fi
    if [ "$ATTACH_MS" = "auto" ]; then if [ "$n" -le 20 ]; then att=0; else att=10; fi; else att=$ATTACH_MS; fi
    # Registration must finish before UEs stop (simTime-1): last UE starts at
    # max(2, attachEnd+1) + n*stag; allow 4s after that.
    simTime=$(awk -v n="$n" -v s="$stag" -v a="$att" 'BEGIN{e=0.01+n*a/1000; st=(e+1>2)?e+1:2; printf "%d", st + n*s + 4 + 0.999}')
    if [ "$GNBS" = "auto" ]; then ngnb=$(( (n + UES_PER_GNB - 1) / UES_PER_GNB )); else ngnb=$GNBS; fi

    for trial in $(seq 1 "$TRIALS"); do
      echo "  UEs=$n gNBs=$ngnb trial $trial/$TRIALS (simTime=${simTime}s)..."
      LOG=$($NS3 run "$TARGET --sigAlg=$sigAlg --kemGroup=$kemGroup --realtime=1 --attachSpacingMs=$att \
--numUes=$n --numGnbs=$ngnb --ueStagger=$stag --ueSpacing=$SPACING --amfServers=$AMF_SERVERS --simTime=$simTime" 2>&1)

      # A run that crashed never prints the summary block.
      run_ok=1; echo "$LOG" | grep -q '^\[SUMMARY\]' || run_ok=0

      # Every EAP-TLS flight, both directions, every UE.
      flight_bytes=$(echo "$LOG" | grep -E '^\[(UE-[0-9]+|AMF)\] EAP-TLS flight #' | grep -oP '[0-9]+(?=B  cpuCost)')
      total_bytes=$(echo "$flight_bytes" | awk 'NF{s+=$1} END{print s+0}')
      msg_count=$(echo "$flight_bytes" | grep -c '[0-9]')

      # Per-UE total registration latency, one value per UE that finished.
      lats=$(echo "$LOG" | grep -E '^\[UE-[0-9]+\] Registration \+ PDU Session COMPLETE' | grep -oP 'total=\K[0-9.]+')
      registered=$(echo "$lats" | grep -c '[0-9]')

      # rejected = second number of "AMF accept/reject:  A/R"
      ar=$(echo "$LOG" | grep -oP 'AMF accept/reject:\s+\K[0-9]+/[0-9]+' | head -1)
      rejected="${ar#*/}"; rejected="${rejected:-}"

      if [ "$registered" -gt 0 ]; then
        bytes_per_ue=$(awk -v b="$total_bytes" -v r="$registered" 'BEGIN{printf "%.0f", b/r}')
        stats=$(echo "$lats" | sort -n | awk 'NF{a[++n]=$1; s+=$1}
          END{i=int(0.95*n); if(i<0.95*n) i++; if(i<1) i=1;
              printf "%.3f,%.3f,%.3f,%.3f", a[1], s/n, a[i], a[n]}')
      else
        bytes_per_ue=""; stats=",,,"
      fi

      # Total service demand placed on the AMF by the TLS handshakes (ms).
      amf_cpu=$(echo "$LOG" | grep -E '^\[AMF\] EAP-TLS flight #' | grep -oP 'cpuCost=\K[0-9.]+' \
                | awk 'NF{s+=$1} END{printf "%.3f", s}')

      echo "$label,$n,$ngnb,$trial,$stag,$SPACING,$AMF_SERVERS,$registered,$rejected,$total_bytes,$bytes_per_ue,$msg_count,$stats,$amf_cpu,$run_ok" >> "$OUT"
    done
  done
done

echo ""
echo "Done -> $OUT"
if command -v column >/dev/null 2>&1; then column -s',' -t "$OUT" | head -60; else cat "$OUT"; fi
