TARGET_IP=${1:-localhost}
COUNT=${2:-25}

echo "Sending $COUNT ComposePost requests to http://$TARGET_IP:8080 ..."

for i in $(seq 1 $COUNT); do
  (
    HTTP_CODE=$(curl -s -o /tmp/dsb_resp_$i.txt -w "%{http_code}" -X POST \
      http://$TARGET_IP:8080/wrk2-api/post/compose \
      -d "username=username_$((RANDOM % 962 + 1))&user_id=$((RANDOM % 962 + 1))&text=Hello+world+post+$i&media_ids=[]&post_type=0")
    BODY=$(cat /tmp/dsb_resp_$i.txt 2>/dev/null)
    echo "[req $i] HTTP $HTTP_CODE${BODY:+  — $BODY}"
    rm -f /tmp/dsb_resp_$i.txt
  ) &
done
wait
echo "Done."