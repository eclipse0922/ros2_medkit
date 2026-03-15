# Greenwave Demo Recording Runbook

This runbook assumes the `x-medkit-graph` implementation is already available in the checked-out branch and that a Docker container named `greenwave_demo` is running. The script generates its own local manifest and `image_sink.py` runtime files under `.demo/generated/`.

## Prep

From the repo root:

```bash
chmod +x .demo/run_greenwave_demo.sh
./.demo/run_greenwave_demo.sh stop
```

If your container or mounted repo path is different, override them:

```bash
GREENWAVE_DEMO_CONTAINER=<name> \
GREENWAVE_DEMO_CONTAINER_REPO_ROOT=/workspace/ros2_medkit \
./.demo/run_greenwave_demo.sh status
```

## Clip 1: Real Greenwave Metrics

Goal: show that `x-medkit-graph` fills edge metrics from a real `greenwave_monitor`.

```bash
./.demo/run_greenwave_demo.sh start-base
./.demo/run_greenwave_demo.sh clear-image-fault
./.demo/run_greenwave_demo.sh start-bag
./.demo/run_greenwave_demo.sh start-greenwave
sleep 6
./.demo/run_greenwave_demo.sh graph-summary
```

What to look for:
- `edge_count: 1`
- `metrics_status: "active"`
- `frequency_hz` is populated
- `pipeline_status` may be `degraded` with the default looped bag; that is fine for this clip

Optional full payload:

```bash
./.demo/run_greenwave_demo.sh graph
```

## Clip 2: Fault-Driven Broken State

Goal: show the same graph switching to `broken` through the diagnostic bridge and fault path.

```bash
./.demo/run_greenwave_demo.sh start-bridge
sleep 4
./.demo/run_greenwave_demo.sh graph-summary
./.demo/run_greenwave_demo.sh faults
```

What to look for:
- `pipeline_status: "broken"`
- `metrics_status: "error"`
- `error_reason: "topic_stale"`
- `bottleneck_edge: null`

## Clip 3: Function-Level SSE

Goal: show the same graph resource through cyclic subscriptions.

```bash
./.demo/run_greenwave_demo.sh create-sse
./.demo/run_greenwave_demo.sh stream-sse
```

What to look for:
- a successful subscription response from `create-sse`
- `data:` frames carrying the same `x-medkit-graph` payload shape as the GET endpoint

## Suggested Recording Order

1. Record clip 1 as the metrics clip.
2. Record clip 3 separately so the SSE frame is easy to read.
3. Record clip 2 last so the broken state does not contaminate earlier takes.

## Cleanup

When the recording is done:

```bash
./.demo/run_greenwave_demo.sh stop
```

## Troubleshooting

Check the current state:

```bash
./.demo/run_greenwave_demo.sh status
```

Known behavior with the default bag:
- `quickstart.bag --loop` is good enough for the demo, but once the diagnostic bridge is enabled it can drive the stale-fault path quickly.
- If the metrics clip starts in a noisy state, run `stop`, then start over from `start-base`.
