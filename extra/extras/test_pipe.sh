sshpass -p "1234" ssh -o "StrictHostKeyChecking=no" shrest@10.5.30.93 "echo '1234' | sudo -S -p '' bash -c 'sudo -E python3 -u ~/bcc-latest/src/new-architecture-USC.py -p 123 2>&1 | tee -a ~/bcc-latest/src/live_single_test8.log'" &
PID=$!
sleep 15
sshpass -p "1234" ssh -o "StrictHostKeyChecking=no" shrest@10.5.30.93 "echo '1234' | sudo -S pkill -2 -x python3"
wait $PID
