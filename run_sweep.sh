#!/usr/bin/env bash
# Runs the v2n-ue-registration simulation across multiple certificate /
# key-exchange configurations, multiple trials each.
#
# Produces TWO files:
#   sweep_summary.csv  — one row per (config, trial): total handshake
#                        bytes, message count, and total registration
#                        latency, as direct columns. This is the table
#                        you actually want for comparing configs.
#   sweep_results.csv  — the detailed per-flight/per-UE raw data, kept
#                        for traceability/debugging if a summary number
#                        ever looks surprising and you want to see where
#                        it came from.
#
# Usage:
#   cd ~/ns-3-dev
#   ./run_sweep.sh                # default: 3 configs x 5 trials
#   TRIALS=10 ./run_sweep.sh      # override trial count
#
# Uses --realtime=0 for speed (byte counts, flight counts, and reported
# simulated delays are IDENTICAL in realtime vs fast mode — only the
# program's own wall-clock runtime differs).

set -u
TRIALS="${TRIALS:-5}"
DETAIL_OUT="sweep_results.csv"
SUMMARY_OUT="sweep_summary.csv"
NS3_TARGET="v2n-ue-registration"

# Each entry: label,sigAlg,kemGroup
#
# "classical" vs "kem-only" isolates the Diffie-Hellman-vs-KEM key-exchange
# swap specifically: both use RSA certificates, so the ONLY thing that
# differs between those two rows is ECDHE (classical DH) vs ML-KEM-768
# (post-quantum KEM). Comparing "classical" vs "pure-pqc" instead would
# change BOTH the signature algorithm AND the key exchange at once, so it
# can't tell you how much of that difference is from the KEM swap alone.
CONFIGS=(
  "classical,RSA,ECDHE"
  "kem-only,RSA,MLKEM768"
  "hybrid-pqc,ML-DSA-44,X25519MLKEM768"
  "pure-pqc,ML-DSA-44,MLKEM768"
)

echo "config,trial,role,ue,flight,bytes,cpu_cost_ms,eaptls_wire_ms,total_reg_ms,negotiated_group,peer_sig_alg" > "$DETAIL_OUT"
echo "config,trial,total_bytes,message_count,avg_total_latency_ms,negotiated_group,peer_sig_alg" > "$SUMMARY_OUT"

for cfg in "${CONFIGS[@]}"; do
  IFS=',' read -r label sigAlg kemGroup <<< "$cfg"
  echo "=== Config: $label (sigAlg=$sigAlg kemGroup=$kemGroup) ==="

  for trial in $(seq 1 "$TRIALS"); do
    echo "  trial $trial/$TRIALS..."
    LOG=$(./ns3 run "$NS3_TARGET --sigAlg=$sigAlg --kemGroup=$kemGroup --realtime=0" 2>&1)

    # ---- Detailed rows (unchanged from before — kept for traceability) ----
    echo "$LOG" | grep -E '^\[UE-[0-9]+\] EAP-TLS flight #' | while read -r line; do
      ue=$(echo "$line" | grep -oP '\[UE-\K[0-9]+')
      flight=$(echo "$line" | grep -oP 'flight #\K[0-9]+')
      bytes=$(echo "$line" | grep -oP '\K[0-9]+(?=B  cpuCost)')
      cost=$(echo "$line" | grep -oP 'cpuCost=\K[0-9.]+')
      echo "$label,$trial,UE,$ue,$flight,$bytes,$cost,,,," >> "$DETAIL_OUT"
    done
    echo "$LOG" | grep -E '^\[AMF\] EAP-TLS flight #' | while read -r line; do
      ue=$(echo "$line" | grep -oP 'UE 7\.0\.0\.\K[0-9]+')
      flight=$(echo "$line" | grep -oP 'flight #\K[0-9]+')
      bytes=$(echo "$line" | grep -oP '\K[0-9]+(?=B  cpuCost)')
      cost=$(echo "$line" | grep -oP 'cpuCost=\K[0-9.]+')
      echo "$label,$trial,AMF,$ue,$flight,$bytes,$cost,,,," >> "$DETAIL_OUT"
    done
    echo "$LOG" | grep -E '^\[UE-[0-9]+\] EAP-TLS SUCCESS' | while read -r line; do
      ue=$(echo "$line" | grep -oP '\[UE-\K[0-9]+')
      wire=$(echo "$line" | grep -oP 'wireTime=\K[0-9.]+')
      group=$(echo "$line" | grep -oP 'group=\K[^ ]+')
      sigalg=$(echo "$line" | grep -oP 'peerCertSigAlg=\K[^ ]+')
      echo "$label,$trial,SUMMARY,$ue,,,,$wire,,$group,$sigalg" >> "$DETAIL_OUT"
    done
    echo "$LOG" | grep -E '^\[UE-[0-9]+\] Registration \+ PDU Session COMPLETE' | while read -r line; do
      ue=$(echo "$line" | grep -oP '\[UE-\K[0-9]+')
      total=$(echo "$line" | grep -oP 'total=\K[0-9.]+')
      echo "$label,$trial,TOTAL,$ue,,,,,$total,,"  >> "$DETAIL_OUT"
    done

    # ---- Summary row: total bytes, message count, latency, direct ----
    # (Computed in THIS shell, not inside the piped `while` loops above,
    # which run in subshells and can't set variables visible out here.)

    # Every EAP-TLS flight, both directions (UE-sent + AMF-sent), across
    # both UEs in this trial — bytes and count.
    all_bytes=$(echo "$LOG" | grep -E '^\[(UE-[0-9]+|AMF)\] EAP-TLS flight #' \
                | grep -oP '[0-9]+(?=B  cpuCost)')
    total_bytes=$(echo "$all_bytes" | awk 'NF{s+=$1} END{print s+0}')
    message_count=$(echo "$all_bytes" | grep -c '[0-9]')

    # Total registration latency, averaged across both UEs in this trial.
    all_totals=$(echo "$LOG" | grep -E '^\[UE-[0-9]+\] Registration \+ PDU Session COMPLETE' \
                 | grep -oP 'total=\K[0-9.]+')
    avg_latency=$(echo "$all_totals" | awk 'NF{s+=$1; n++} END{if(n>0) printf "%.3f", s/n; else print ""}')

    # Negotiated group / cert sig alg — same for both UEs within a trial,
    # so the first match is representative.
    group=$(echo "$LOG" | grep -oP 'group=\K[^ ]+' | head -1)
    sigalg=$(echo "$LOG" | grep -oP 'peerCertSigAlg=\K[^ ]+' | head -1)

    echo "$label,$trial,$total_bytes,$message_count,$avg_latency,$group,$sigalg" >> "$SUMMARY_OUT"
  done
done

echo ""
echo "Done."
echo "  Summary table (what you want):  $SUMMARY_OUT"
echo "  Detailed per-flight data:        $DETAIL_OUT"
echo ""
echo "Quick peek at the summary:"
column -s',' -t "$SUMMARY_OUT" | head -20
