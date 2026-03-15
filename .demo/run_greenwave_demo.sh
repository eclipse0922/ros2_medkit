#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKTREE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMMON_GIT_DIR="$(git -C "${WORKTREE_ROOT}" rev-parse --git-common-dir)"
COMMON_ROOT="$(dirname "${COMMON_GIT_DIR}")"
CONTAINER_COMMON_ROOT="${GREENWAVE_DEMO_CONTAINER_REPO_ROOT:-/workspace/ros2_medkit}"

if [[ "${WORKTREE_ROOT}" == "${COMMON_ROOT}" ]]; then
  WORKTREE_RELATIVE=""
  CONTAINER_WORKTREE_ROOT="${CONTAINER_COMMON_ROOT}"
else
  WORKTREE_RELATIVE="${WORKTREE_ROOT#${COMMON_ROOT}/}"
  CONTAINER_WORKTREE_ROOT="${CONTAINER_COMMON_ROOT}/${WORKTREE_RELATIVE}"
fi

CONTAINER_NAME="${GREENWAVE_DEMO_CONTAINER:-greenwave_demo}"
API_BASE="${GREENWAVE_DEMO_API_BASE:-http://127.0.0.1:8080/api/v1}"
FUNCTION_ID="${GREENWAVE_DEMO_FUNCTION_ID:-image-pipeline}"
TOPIC_NAME="${GREENWAVE_DEMO_TOPIC:-/image}"
BAG_PATH="${GREENWAVE_DEMO_BAG_PATH:-/tmp/quickstart.bag}"
LAST_SUBSCRIPTION_FILE="${GREENWAVE_DEMO_LAST_SUBSCRIPTION:-${WORKTREE_ROOT}/.demo/last_subscription.json}"

HOST_GENERATED_DIR="${WORKTREE_ROOT}/.demo/generated"
HOST_MANIFEST_PATH="${HOST_GENERATED_DIR}/greenwave_demo_manifest.yaml"
HOST_IMAGE_SINK_PATH="${HOST_GENERATED_DIR}/image_sink.py"
MANIFEST_PATH="${CONTAINER_WORKTREE_ROOT}/.demo/generated/greenwave_demo_manifest.yaml"
IMAGE_SINK_PATH="${CONTAINER_WORKTREE_ROOT}/.demo/generated/image_sink.py"

die() {
  echo "error: $*" >&2
  exit 1
}

require_container() {
  docker inspect -f '{{.State.Running}}' "${CONTAINER_NAME}" >/dev/null 2>&1 ||
    die "container '${CONTAINER_NAME}' is not running"
}

ensure_demo_assets() {
  mkdir -p "${HOST_GENERATED_DIR}"

  cat >"${HOST_MANIFEST_PATH}" <<'EOF'
manifest_version: "1.0"

metadata:
  name: "greenwave-demo"
  version: "1.0.0"
  description: "Local x-medkit-graph + Greenwave demo manifest"

discovery:
  unmanifested_nodes: "ignore"
  inherit_runtime_resources: true
  allow_manifest_override: true

areas:
  - id: demo
    name: "Demo"

components:
  - id: bag-player-comp
    name: "Bag Player"
    area: demo
    type: "replay"

  - id: image-sink-comp
    name: "Image Sink"
    area: demo
    type: "consumer"

apps:
  - id: bag-player
    name: "Bag Player"
    is_located_on: "bag-player-comp"
    ros_binding:
      node_name: "bag_player"
      namespace: "/"

  - id: image-sink
    name: "Image Sink"
    is_located_on: "image-sink-comp"
    ros_binding:
      node_name: "image_sink"
      namespace: "/"

functions:
  - id: image-pipeline
    name: "Image Pipeline"
    description: "Bag replay to sink function for x-medkit-graph demo"
    hosts:
      - bag-player
      - image-sink
EOF

  cat >"${HOST_IMAGE_SINK_PATH}" <<'EOF'
#!/usr/bin/env python3

import rclpy
from rclpy.node import Node
from sensor_msgs.msg import Image


class ImageSink(Node):
    def __init__(self) -> None:
        super().__init__("image_sink")
        self._count = 0
        self.create_subscription(Image, "/image", self._callback, 10)

    def _callback(self, _msg: Image) -> None:
        self._count += 1
        if self._count % 30 == 0:
            self.get_logger().info(f"received {self._count} image messages")


def main() -> None:
    rclpy.init()
    node = ImageSink()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
EOF

  chmod +x "${HOST_IMAGE_SINK_PATH}"
}

container_exec() {
  local cmd="${1}"
  docker exec \
    -e DEMO_MANIFEST_PATH="${MANIFEST_PATH}" \
    -e DEMO_IMAGE_SINK_PATH="${IMAGE_SINK_PATH}" \
    -e DEMO_BAG_PATH="${BAG_PATH}" \
    -e DEMO_TOPIC_NAME="${TOPIC_NAME}" \
    -e DEMO_FUNCTION_ID="${FUNCTION_ID}" \
    "${CONTAINER_NAME}" \
    bash -lc "${cmd}"
}

wait_gateway() {
  local attempt
  for attempt in $(seq 1 50); do
    if curl -sf "${API_BASE}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  die "gateway did not become ready on ${API_BASE}"
}

fetch_graph_json() {
  local attempt
  for attempt in $(seq 1 25); do
    if curl -sf "${API_BASE}/functions/${FUNCTION_ID}/x-medkit-graph"; then
      return 0
    fi
    sleep 0.2
  done
  die "graph endpoint did not become ready for function '${FUNCTION_ID}'"
}

stop_demo_processes() {
  require_container
  docker exec -i "${CONTAINER_NAME}" python3 - <<'PY'
import os
import signal
import subprocess

patterns = [
    "image_sink.py",
    "ros2 run ros2_medkit_gateway gateway_node --ros-args -p discovery.mode:=hybrid",
    "/ros2_medkit_gateway/lib/ros2_medkit_gateway/gateway_node --ros-args -p discovery.mode:=hybrid",
    "ros2 run ros2_medkit_diagnostic_bridge diagnostic_bridge_node",
    "/ros2_medkit_diagnostic_bridge/lib/ros2_medkit_diagnostic_bridge/diagnostic_bridge_node",
    "ros2 launch greenwave_monitor hz.launch.py",
    "/greenwave_monitor/lib/greenwave_monitor/greenwave_monitor",
    "ros2 bag play /tmp/quickstart.bag",
]

output = subprocess.check_output(["ps", "-eo", "pid=,args="], text=True)
for line in output.splitlines():
    line = line.strip()
    if not line:
        continue
    pid_str, cmd = line.split(None, 1)
    if any(pattern in cmd for pattern in patterns):
        try:
            os.kill(int(pid_str), signal.SIGKILL)
        except ProcessLookupError:
            pass
PY
}

start_base() {
  require_container
  ensure_demo_assets
  stop_demo_processes
  container_exec '
    set -e
    source /opt/ros/jazzy/setup.bash
    source /workspace/ros2_medkit/install-docker-graph/setup.bash
    source /workspace/ros2_medkit/install-docker-fix/setup.bash
    nohup python3 "${DEMO_IMAGE_SINK_PATH}" >/tmp/demo-image-sink.log 2>&1 &
    nohup ros2 run ros2_medkit_gateway gateway_node --ros-args \
      -p discovery.mode:=hybrid \
      -p discovery.manifest_path:="${DEMO_MANIFEST_PATH}" \
      -p discovery.manifest_strict_validation:=false \
      -p refresh_interval_ms:=1000 >/tmp/demo-gateway.log 2>&1 &
  '
  wait_gateway
}

start_bag() {
  require_container
  container_exec '
    set -e
    source /opt/ros/jazzy/setup.bash
    nohup ros2 bag play "${DEMO_BAG_PATH}" --topics "${DEMO_TOPIC_NAME}" --loop --remap __node:=bag_player \
      >/tmp/demo-bag.log 2>&1 &
  '
}

start_greenwave() {
  require_container
  container_exec '
    set -e
    source /opt/ros/jazzy/setup.bash
    source /workspace/greenwave_ws/install/setup.bash
    nohup ros2 launch greenwave_monitor hz.launch.py gw_monitored_topics:="[\"${DEMO_TOPIC_NAME}\"]" \
      >/tmp/demo-greenwave.log 2>&1 &
  '
}

start_bridge() {
  require_container
  container_exec '
    set -e
    source /opt/ros/jazzy/setup.bash
    source /workspace/ros2_medkit/install-docker-graph/setup.bash
    nohup ros2 run ros2_medkit_diagnostic_bridge diagnostic_bridge_node >/tmp/demo-diagnostic-bridge.log 2>&1 &
  '
}

clear_image_fault() {
  require_container
  container_exec "
    set -e
    source /opt/ros/jazzy/setup.bash
    source /workspace/ros2_medkit/install-docker-fix/setup.bash
    ros2 service call /fault_manager/clear_fault ros2_medkit_msgs/srv/ClearFault '{fault_code: IMAGE}' || true
  "
}

status() {
  require_container
  echo "== health =="
  if curl -sf "${API_BASE}/health" >/dev/null 2>&1; then
    echo "gateway: running"
  else
    echo "gateway: stopped"
  fi
  echo
  echo "== processes =="
  container_exec 'ps -eo pid,cmd | egrep "diagnostic_bridge|greenwave_monitor|ros2 bag|image_sink|gateway_node" | grep -v grep | grep -v "<defunct>" || true'
}

graph_json() {
  local graph_payload
  graph_payload="$(fetch_graph_json)"
  printf '%s\n' "${graph_payload}" | python3 -m json.tool
}

graph_summary() {
  local graph_payload
  graph_payload="$(fetch_graph_json)"
  printf '%s\n' "${graph_payload}" | python3 -c '
import json
import sys

body = json.load(sys.stdin)["x-medkit-graph"]
edge = body["edges"][0] if body["edges"] else {}
metrics = edge.get("metrics", {})
summary = {
    "graph_id": body["graph_id"],
    "pipeline_status": body["pipeline_status"],
    "bottleneck_edge": body["bottleneck_edge"],
    "node_count": len(body["nodes"]),
    "edge_count": len(body["edges"]),
    "metrics_status": metrics.get("metrics_status"),
    "error_reason": metrics.get("error_reason"),
    "frequency_hz": metrics.get("frequency_hz"),
    "latency_ms": metrics.get("latency_ms"),
    "drop_rate_percent": metrics.get("drop_rate_percent"),
}
print(json.dumps(summary, indent=2))
'
}

faults() {
  curl -s "${API_BASE}/faults" | python3 -m json.tool
}

create_sse() {
  fetch_graph_json >/dev/null
  mkdir -p "$(dirname "${LAST_SUBSCRIPTION_FILE}")"
  local payload
  payload=$(
    python3 - <<PY
import json
payload = {
    "resource": "/api/v1/functions/${FUNCTION_ID}/x-medkit-graph",
    "interval": "normal",
    "duration": 30,
    "protocol": "sse",
}
print(json.dumps(payload))
PY
  )
  curl -sf -X POST "${API_BASE}/functions/${FUNCTION_ID}/cyclic-subscriptions" \
    -H 'Content-Type: application/json' \
    -d "${payload}" | tee "${LAST_SUBSCRIPTION_FILE}"
  echo
  echo "saved ${LAST_SUBSCRIPTION_FILE}" >&2
}

stream_sse() {
  local sub_id="${1:-}"
  if [[ -z "${sub_id}" ]]; then
    [[ -f "${LAST_SUBSCRIPTION_FILE}" ]] || die "no saved subscription file at ${LAST_SUBSCRIPTION_FILE}"
    sub_id="$(python3 - "${LAST_SUBSCRIPTION_FILE}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    print(json.load(stream)["id"])
PY
)"
  fi
  curl -N "${API_BASE}/functions/${FUNCTION_ID}/cyclic-subscriptions/${sub_id}/events"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") <command>

Commands:
  start-base        generate demo assets, then start image_sink + gateway on a clean slate
  start-bag         start looping bag replay for ${TOPIC_NAME}
  start-greenwave   start real greenwave_monitor
  start-bridge      start diagnostic bridge
  clear-image-fault clear the IMAGE fault in FaultManager
  stop              stop demo processes started by this helper
  status            show gateway health and relevant processes
  graph             pretty-print the full graph JSON
  graph-summary     print a compact graph summary for recording
  faults            pretty-print /api/v1/faults
  create-sse        create a function-level cyclic subscription and save it locally
  stream-sse [id]   stream SSE events for the given or last-created subscription

Runtime files:
  ${HOST_GENERATED_DIR}/greenwave_demo_manifest.yaml
  ${HOST_GENERATED_DIR}/image_sink.py
  ${LAST_SUBSCRIPTION_FILE}

Environment overrides:
  GREENWAVE_DEMO_CONTAINER
  GREENWAVE_DEMO_CONTAINER_REPO_ROOT
  GREENWAVE_DEMO_API_BASE
  GREENWAVE_DEMO_FUNCTION_ID
  GREENWAVE_DEMO_TOPIC
  GREENWAVE_DEMO_BAG_PATH
  GREENWAVE_DEMO_LAST_SUBSCRIPTION
EOF
}

command="${1:-}"
case "${command}" in
  start-base)
    start_base
    ;;
  start-bag)
    start_bag
    ;;
  start-greenwave)
    start_greenwave
    ;;
  start-bridge)
    start_bridge
    ;;
  clear-image-fault)
    clear_image_fault
    ;;
  stop)
    stop_demo_processes
    ;;
  status)
    status
    ;;
  graph)
    graph_json
    ;;
  graph-summary)
    graph_summary
    ;;
  faults)
    faults
    ;;
  create-sse)
    create_sse
    ;;
  stream-sse)
    stream_sse "${2:-}"
    ;;
  ""|help|-h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
