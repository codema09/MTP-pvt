sudo systemctl enable --now docker

sudo usermod -aG docker $USER

docker-compose up -d

echo "Waiting for nginx gateway on port 8080..."
until curl -sf http://localhost:8080/ > /dev/null 2>&1; do
    sleep 2
done
echo "Gateway ready."

source /home/khr/homefr/MTP/ebpf/bcc-latest/extras/venv/bin/activate

echo "Registering Users..."
python3 scripts/init_social_graph.py --ip localhost --port 8080

docker ps --format '{{.Names}}' | xargs -I{} sh -c \
  'echo -n "{}: "; docker inspect --format "{{.State.Pid}}" {}'

echo "PIDs: $(docker ps --format '{{.Names}}' | xargs -I{} docker inspect --format '{{.State.Pid}}' {} | tr '\n' ' ')"

#sudo -E TERM=xterm-256color python3 -u new-architecture-USC.py -p 2013 2059 1830 1965 1870 2215 2851 2796 2264 1792 1918 2304 2175 2641 2721 2480 2604 2538 >logs/first.ansi 2>&1

#docker-compose down -v