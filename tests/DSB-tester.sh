TARGET_IP=${1:-localhost}

for i in $(seq 1 25); do
  curl -s -X POST http://$TARGET_IP:8080/wrk2-api/post/compose \
    -d "username=username_$((RANDOM % 962 + 1))&user_id=$((RANDOM % 962 + 1))&text=Hello+world+post+$i&media_ids=[]&post_type=0" &
done
wait