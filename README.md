# Distributed eBPF Profiling Orchestrator (25-Node Topology)

This directory contains the automated orchestration tools to deploy the **DeathStarBench Social Network** natively across 25 VirtualBox VMs without relying on Docker Swarm UDP Overlays. Included are the background eBPF profilers that independently track C++ microservice PIDs and silently stream high-resolution telemetry back to your central host.

To bring up the entire framework from scratch, open **four separate terminals** and execute the commands below in order:

---

### Terminal 1: Start the Central Telemetry Ingestion Server
This terminal hosts the global `log_handler.py` endpoint. It sits on port `5000` waiting to receive real-time RPC span logs natively over the network from the distributed `new-architecture-USC.py` sniffers.

```bash
cd ~/bcc-latest/src
python3 log_handler.py
```
*(Leave this running in the background).*

---

### Terminal 2: Automated Cluster Topology Deployment
In this terminal, we execute the master cluster deployment orchestrator. It mathematically dictates static IP bindings to eliminate DNS timeouts, packages the patched codebase, and synchronously coordinates native Gigabit networking across all 25 VMs.

```bash
cd ~/bcc-latest

git checkout DSB/socialNetwork/nginx-web-server/lua-scripts/ \
             DSB/socialNetwork/nginx-web-server/jaeger-config.json \
             DSB/socialNetwork/config/service-config.json

# Launch the orchestrator (Takes ~5 minutes)
bash deploy_all_node.sh
```

**What the script does:**
1. Erases all broken container states natively on targets.
2. Packages the codebase and initiates `docker compose` across `10.5.30.94 - 117`.
3. Waits for Thrift services to boot and initializes a 18,000-user database graph.
4. Injects detached `tmux` sessions on all 25 nodes running `new-architecture-USC.py` bound to your local IP stream.

---

### Terminal 3: Traffic Generation & Baseline Stress Testing
Once Terminal 2 successfully says **"✅ Distributed Teardown cleanly completed. Exiting entirely."**, the cluster is entirely live and profiling. Fire traffic into the Nginx ingress to observe native Thrift network functionality:

```bash
cd ~/bcc-latest/tests

# Send 50 concurrent Posts directly to the Edge Node (10.5.30.93)
bash DSB-tester.sh 10.5.30.93 50
```
*You should see 50 sequential `HTTP 200 — Successfully upload post` responses
**After receiving the above, send a (ctrl+C) termination signal to the script on Terminal 2 to wrap up the logging in each VM and send them all to the central log_handler we ran in first terminal.


### Terminal 4: Visualizing eBPF Architecture Metrics
Switch back to **Terminal 1**. You will see vast amounts of span telemetry flowing in from the distributed VirtualBox VMs because of your load test! You can extract this collected graph natively across the pipeline:

(In Terminal 4):
```bash
cd ~/bcc-latest

# Query the running Log Handler for the comprehensive DAG
curl http://localhost:5000/graph/print > src/graphs/final_profiling_trace.log

# View the final graph topology 
cat src/graphs/final_profiling_trace.log
```
