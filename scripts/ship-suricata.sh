#!/bin/bash
# ship-suricata.sh — forwards Suricata alert events to Splunk HEC
# Reads new lines from eve.json, keeps only alert events, posts them to HEC.
# Runs via cron every 2 minutes:  */2 * * * * /opt/ship-suricata.sh
#
# SECURITY: Replace the placeholder token before use.
# Never commit real tokens to version control.

SPLUNK_IP="127.0.0.1"
TOKEN="YOUR_HEC_TOKEN_HERE"          # HEC token from Splunk
EVE="/var/log/suricata/eve.json"
BOOKMARK="/opt/suricata-bookmark"

LAST=$(cat "$BOOKMARK" 2>/dev/null || echo 0)
TOTAL=$(wc -l < "$EVE")

if [ "$TOTAL" -le "$LAST" ]; then
  echo "nothing new"
  exit 0
fi

# send only new alert events to HEC
tail -n +$((LAST+1)) "$EVE" | grep '"event_type":"alert"' | while read -r line; do
  curl -k -s "https://$SPLUNK_IP:8088/services/collector/event" \
    -H "Authorization: Splunk $TOKEN" \
    -d "{\"index\":\"suricata\",\"sourcetype\":\"suricata:alert\",\"event\":$line}" > /dev/null
done

echo "$TOTAL" > "$BOOKMARK"
echo "shipped alerts up to line $TOTAL"
