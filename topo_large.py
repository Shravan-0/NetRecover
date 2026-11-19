#!/usr/bin/env python3

import json
from power_control import execution_permit, PowerDisabled
from system_health import HealthCache, collect_health, worker_pids
from classified_recovery import recover_classified
import functools
import hmac
import sqlite3
import re
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from link_recovery import recover_link, remove_link_recovery_flows
from recovery_history import owner_alive
from link_state import read_ports, edge_state, set_link_fault

LINK_PORT_BACKUPS = {}
from runtime_recovery import (ControllerManager, controller_health, recover_controller,
                              recover_service, service_health)


def current_controller_health():
    return controller_health(ControllerManager(Path(__file__).resolve().parent))


def current_service_health():
    return service_health(network, service_process_pids)

NETWORK_LOCK = threading.RLock()
LINK_RESULTS = {}
SYSTEM_HEALTH = HealthCache()
HEALTH_STOPPED = threading.Event()


def serialized_network(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        with NETWORK_LOCK:
            return function(*args, **kwargs)
    return wrapped


def observed_network(function):
    """Read endpoints return unavailable promptly rather than queue behind long actions."""
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        if not NETWORK_LOCK.acquire(blocking=False):
            raise RuntimeError('Network operation/verification in progress; observation unavailable')
        try:
            return function(*args, **kwargs)
        finally:
            NETWORK_LOCK.release()
    return wrapped



CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 8765

# Only this predefined link can be controlled through the API.
FAULT_LINK = ("s2", "s3")
link_is_down = False

# Only this predefined switch can be misconfigured through the API.
FAULT_SWITCH = "s4"
EXPECTED_CONTROLLER = "tcp:127.0.0.1:6633"
WRONG_CONTROLLER = "tcp:127.0.0.1:9999"
EXPECTED_PROTOCOL = "OpenFlow13"
WRONG_PROTOCOL = "OpenFlow10"
switch_is_misconfigured = False
service_is_stopped = False
process_is_stopped = False
controller_is_disconnected = False
path_is_down = False
network = None
SERVICE_SCRIPT = Path(__file__).resolve().with_name("health_service.py")
PROCESS_PID_FILE = "/tmp/acn_fault_worker.pid"
ALL_SWITCHES = ("s1", "s2", "s3", "s4", "s5")
PATH_LINKS = (("s3", "s5"),)


class ACNTopology(Topo):
    def build(self):
        switches = {
            name: self.addSwitch(name, protocols="OpenFlow13")
            for name in ("s1", "s2", "s3", "s4", "s5")
        }

        for a, b in (
            ("s1", "s2"),
            ("s2", "s3"),
            ("s2", "s4"),
            ("s3", "s5"),
            ("s4", "s5"),
        ):
            self.addLink(switches[a], switches[b])

        host_switches = {
            "h1": "s1",
            "h2": "s2",
            "h3": "s3",
            "h4": "s1",
            "h5": "s4",
            "h6": "s5",
            "h7": "s4",
            "h8": "s5",
        }

        for index, (host, switch) in enumerate(host_switches.items(), 1):
            self.addHost(host, ip=f"10.0.0.{index}/24")
            self.addLink(host, switches[switch])


def parse_control_payload(raw, content_length):
    if content_length < 1 or content_length > 1024:
        raise ValueError("Invalid request size")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Invalid JSON request")
    action = payload.get("action")
    if action not in ("enable", "disable"):
        raise ValueError("Action must be enable or disable")
    return action


def switch_cmd(command):
    try:
        args = shlex.split(command)
        if args and args[0] == "ovs-vsctl":
            result = subprocess.run(args, capture_output=True, text=True, timeout=4)
            if result.returncode == 0:
                return result.stdout.strip()
    except Exception:
        pass
    if network is None:
        raise RuntimeError("Mininet network is not running")
    switch = network.get(FAULT_SWITCH)
    if switch is None:
        raise RuntimeError(f"Switch {FAULT_SWITCH} was not found")
    return switch.cmd(command).strip()


@observed_network
def read_switch_state():
    global switch_is_misconfigured

    controller = switch_cmd(
        f"ovs-vsctl --timeout=4 get-controller {FAULT_SWITCH}"
    )
    protocols = switch_cmd(
        f"ovs-vsctl --timeout=4 get bridge {FAULT_SWITCH} protocols"
    )

    # The controller may be wrong because the controller fault is active.
    # That alone must not be reported as a switch-configuration fault.
    protocol_ok = EXPECTED_PROTOCOL.lower() in protocols.lower()
    controller_ok = EXPECTED_CONTROLLER in controller

    switch_is_misconfigured = (
        not protocol_ok
        or (not controller_ok and not controller_is_disconnected)
    )

    return {
        "switch": FAULT_SWITCH,
        "controller": controller,
        "protocols": protocols,
        "state": "fault" if switch_is_misconfigured else "ok",
    }


def apply_switch_fault(action):
    global switch_is_misconfigured

    switch_is_misconfigured = action == "enable"

    # Preserve the controller fault if it is also active.
    s4_controller = (
        WRONG_CONTROLLER
        if controller_is_disconnected or switch_is_misconfigured
        else EXPECTED_CONTROLLER
    )

    s4_protocol = (
        WRONG_PROTOCOL
        if switch_is_misconfigured
        else EXPECTED_PROTOCOL
    )

    switch_cmd(
        f"ovs-vsctl set-controller {FAULT_SWITCH} {s4_controller}"
    )
    switch_cmd(
        f"ovs-vsctl set bridge {FAULT_SWITCH} protocols={s4_protocol}"
    )

    return read_switch_state()


def host_cmd(host_name, command):
    if network is None:
        raise RuntimeError("Mininet network is not running")
    host = network.get(host_name)
    if host is None:
        raise RuntimeError(f"Host {host_name} was not found")
    return host.cmd(command).strip()

def initialize_service_config():
    """Create the healthy default configuration inside Mininet host h2."""
    return host_cmd("h2", "printf 'mode=ok\\n' > /tmp/service.conf")


# ACN_SERVICE_NAMESPACE_V1
def service_process_pids():
    """Find this project's service only inside the current h2 network namespace."""
    if network is None:
        raise RuntimeError("Mininet network is not running")
    host = network.get("h2")
    if host is None or not getattr(host, "pid", None):
        raise RuntimeError("Current h2 shell PID is unavailable")

    proc_root = Path("/proc")
    expected_ns = os.readlink(str(proc_root / str(host.pid) / "ns/net"))
    expected_script = SERVICE_SCRIPT.resolve()
    found = []

    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if os.readlink(str(entry / "ns/net")) != expected_ns:
                continue
            args = (entry / "cmdline").read_bytes().split(b"\0")
            for raw in args[1:]:
                if not raw:
                    continue
                candidate = Path(os.fsdecode(raw))
                if candidate.name != expected_script.name:
                    continue
                if not candidate.is_absolute():
                    candidate = Path(os.readlink(str(entry / "cwd"))) / candidate
                if candidate.resolve() == expected_script:
                    found.append(int(entry.name))
                    break
        except (OSError, ValueError):
            # Processes can exit while /proc is being inspected.
            continue
    return sorted(found)


def service_process_running():
    return bool(service_process_pids())


def apply_service_fault(action):
    global service_is_stopped
    if action not in ("enable", "disable"):
        raise ValueError("Action must be enable or disable")

    if action == "enable":
        for pid in service_process_pids():
            # Recheck namespace/script membership immediately before signaling.
            if pid in service_process_pids():
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 2
        while service_process_running() and time.monotonic() < deadline:
            time.sleep(0.05)
    else:
        if not service_process_running():
            script = shlex.quote(str(SERVICE_SCRIPT))
            host_cmd(
                "h2",
                f"nohup python3 {script} >/tmp/health_service.log 2>&1 </dev/null &",
            )
            deadline = time.monotonic() + 2
            while not service_process_running() and time.monotonic() < deadline:
                time.sleep(0.05)

    service_is_stopped = not service_process_running()
    return {
        "id": "service",
        "state": "fault" if service_is_stopped else "ok",
        "running": not service_is_stopped,
    }


def process_worker_running():
    return bool(worker_pids(network))


def start_process_worker():
    if not process_worker_running():
        host_cmd(
            "h3",
            f"bash -c 'exec -a acn_fault_worker sleep 86400' >/dev/null 2>&1 & echo $! > {PROCESS_PID_FILE}",
        )
    return process_worker_running()


def apply_process_fault(action):
    global process_is_stopped
    if action == "enable":
        if process_worker_running():
            host_cmd("h3", f"kill $(cat {PROCESS_PID_FILE}) 2>/dev/null || true")
        host_cmd("h3", f"rm -f {PROCESS_PID_FILE}")
        process_is_stopped = not process_worker_running()
    else:
        process_is_stopped = not start_process_worker()
    return {
        "id": "process",
        "state": "fault" if process_is_stopped else "ok",
        "running": not process_is_stopped,
        "target": "h3:sleep-worker",
    }



def switch_cmd_for_status(switch_name):
    try:
        result = subprocess.run(["ovs-vsctl", "--timeout=4", "get-controller", switch_name],
                                capture_output=True, text=True, timeout=4)
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    if network is None:
        raise RuntimeError("Mininet network is not running")
    switch = network.get(switch_name)
    if switch is None:
        raise RuntimeError(f"Switch {switch_name} was not found")
    return switch.cmd(f"ovs-vsctl get-controller {switch_name}").strip()

def apply_controller_fault(action):
    global controller_is_disconnected

    controller_is_disconnected = action == "enable"

    for switch_name in ALL_SWITCHES:
        switch = network.get(switch_name)

        if switch is None:
            raise RuntimeError(f"Switch {switch_name} was not found")

        # s4 is shared with the switch-configuration fault.
        if switch_name == FAULT_SWITCH:
            target = (
                WRONG_CONTROLLER
                if controller_is_disconnected or switch_is_misconfigured
                else EXPECTED_CONTROLLER
            )
        else:
            target = (
                WRONG_CONTROLLER
                if controller_is_disconnected
                else EXPECTED_CONTROLLER
            )

        switch.cmd(f"ovs-vsctl set-controller {switch_name} {target}")

    return {
        "id": "controller",
        "state": "fault" if controller_is_disconnected else "ok",
        "controller": (
            WRONG_CONTROLLER
            if controller_is_disconnected
            else EXPECTED_CONTROLLER
        ),
        "switches": list(ALL_SWITCHES),
    }


def apply_path_fault(action):
    global path_is_down
    state = "down" if action == "enable" else "up"
    # Fail the primary s3-s5 segment while leaving the s2-s4-s5 alternate route.
    for a, b in PATH_LINKS:
        network.configLinkStatus(a, b, state)
    path_is_down = action == "enable"
    return {
        "id": "path",
        "state": "fault" if path_is_down else "ok",
        "links": [f"{a}-{b}" for a, b in PATH_LINKS],
    }


def observed_link_state(node_a, node_b, snapshot=None):
    """Effective link state: real OVS attachment plus actual interface availability."""
    try:
        with NETWORK_LOCK:
            return edge_state(network, node_a, node_b, snapshot)
    except Exception:
        return "unknown"


@observed_network
def collect_observations():
    """Observable topology signals used by detection/classification."""
    switch_state = read_switch_state()
    controller_state = current_controller_health()
    controllers = {name: switch_cmd_for_status(name) for name in ALL_SWITCHES}
    if controller_state and "controllers" in controller_state:
        for name in ALL_SWITCHES:
            target = controller_state["controllers"].get(name)
            if target and ("flags=" in controllers.get(name, "") or not controllers.get(name)):
                controllers[name] = target
    link_snapshot = read_ports()
    links = {
        f"{FAULT_LINK[0]}-{FAULT_LINK[1]}": observed_link_state(*FAULT_LINK, snapshot=link_snapshot),
    }
    for a, b in PATH_LINKS:
        links[f"{a}-{b}"] = observed_link_state(a, b, snapshot=link_snapshot)
    service_running = service_process_running()
    process_running = process_worker_running()
    return {
        "ok": True,
        "switch": {
            "switch": switch_state.get("switch"),
            "controller": switch_state.get("controller"),
            "protocols": switch_state.get("protocols"),
        },
        "controllers": controllers,
        "controller_process_running": controller_state["process_running"],
        "controller_port_listening": controller_state["port_listening"],
        "controller_port_owned": controller_state["port_owned_by_expected_ryu"],
        "controller_connections": {name: row["is_connected"] for name, row in controller_state["switch_connections"].items()},
        "controller_observation_complete": True,
        "links": links,
        "service_running": bool(service_running),
        "process_running": bool(process_running),
    }


def current_edge_states():
    snapshot = read_ports()
    return {"s2-s3": observed_link_state("s2", "s3", snapshot),
            "s3-s5": observed_link_state("s3", "s5", snapshot)}


def independent_system_health():
    return collect_health(network, current_controller_health, current_service_health,
                          read_switch_state, current_edge_states, lambda: worker_pids(network))


class ControlHandler(BaseHTTPRequestHandler):
    def send_json(self, code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_action(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1024:
                raise ValueError("Invalid request size")
            raw = self.rfile.read(length)
            return parse_control_payload(raw, length)
        except (ValueError, json.JSONDecodeError, TypeError) as exc:
            self.send_json(400, {"ok": False, "error": str(exc) or "Invalid JSON request"})
            return None

    def do_GET(self):
        if self.path == "/api/recovery/health":
            self.send_json(200, SYSTEM_HEALTH.get())
        elif self.path == "/api/link/status":
            try:
                state = observed_link_state(*FAULT_LINK)
                self.send_json(200, {
                    "ok": True,
                    "link": f"{FAULT_LINK[0]}-{FAULT_LINK[1]}",
                    "state": state,
                })
            except Exception as exc:
                self.send_json(503, {
                    "ok": False,
                    "error": f"Could not read link status: {exc}",
                })
        elif self.path == "/api/switch/status":
            try:
                state = read_switch_state()
                state["ok"] = True
                self.send_json(200, state)
            except Exception as exc:
                self.send_json(503, {
                    "ok": False,
                    "error": f"Could not read switch state: {exc}",
                })
        elif self.path == "/api/service/status":
            try:
                running = service_process_running()
                self.send_json(200, {"ok": True, "id": "service", "state": "ok" if running else "fault", "running": running})
            except Exception as exc:
                self.send_json(503, {"ok": False, "error": str(exc)})
        elif self.path == "/api/process/status":
            try:
                running = process_worker_running()
                self.send_json(200, {"ok": True, "id": "process", "state": "ok" if running else "fault", "running": running, "target": "h3:sleep-worker"})
            except Exception as exc:
                self.send_json(503, {"ok": False, "error": str(exc)})
        elif self.path == "/api/controller/status":
            try:
                self.send_json(200, current_controller_health())
            except Exception as exc:
                self.send_json(503, {"ok": False, "error": str(exc)})
        elif self.path == "/api/path/status":
            self.send_json(200, {"ok": True, "id": "path", "state": "fault" if path_is_down else "ok", "links": [f"{a}-{b}" for a, b in PATH_LINKS]})
        elif self.path == "/api/health-probe":
            try:
                result = current_service_health()
                self.send_json(200 if result["healthy"] else 503, result)
            except Exception as exc:
                self.send_json(
                    503,
                    {
                        "ok": False,
                        "healthy": False,
                        "error": str(exc),
                        "target": "h2:8080",
                    },
                )
        elif self.path == "/api/observe":
            try:
                self.send_json(200, collect_observations())
            except Exception as exc:
                self.send_json(503, {
                    "ok": False,
                    "error": f"Could not collect observations: {exc}",
                })
        elif self.path == "/health":
            self.send_json(200, {"ok": True, "service": "mininet-control",
                                 "recovery_capabilities": ["alternate_link_v1", "namespace_service_v1", "owned_controller_v1", "stable_link_fault_v2", "shared_power_v1", "classified_recovery_v3", "independent_health_v1"]})
        else:
            self.send_json(404, {"ok": False, "error": "Not found"})

    @serialized_network
    def do_POST(self):
        global link_is_down

        if self.path in ("/api/recovery/link", "/api/recovery/service", "/api/recovery/controller",
                         "/api/recovery/config", "/api/recovery/switch", "/api/recovery/path", "/api/recovery/process"):
            self.recover_link_request()
            return

        if self.path == "/api/link":
            action = self.read_action()
            if action is None:
                return
            try:
                injected = set_link_fault(network, action, Path(__file__).resolve().parent, LINK_PORT_BACKUPS)
                state = injected["state"]
                if action == "disable":
                    remove_link_recovery_flows(network)
                link_is_down = action == "enable"
                info(
                    f"*** Dashboard link action: "
                    f"{FAULT_LINK[0]}-{FAULT_LINK[1]} -> {state}\n"
                )
                self.send_json(200, {
                    "ok": True,
                    "link": f"{FAULT_LINK[0]}-{FAULT_LINK[1]}",
                    "state": state,
                    "physical_verification": injected,
                    "message": (
                        "Link failure enabled"
                        if link_is_down else "Link restored"
                    ),
                })
            except Exception as exc:
                self.send_json(500, {
                    "ok": False,
                    "error": f"Could not change link state: {exc}",
                })
            return

        if self.path == "/api/switch":
            action = self.read_action()
            if action is None:
                return
            try:
                state = apply_switch_fault(action)
                info(
                    f"*** Dashboard switch action: {FAULT_SWITCH} "
                    f"controller={state['controller']} "
                    f"protocols={state['protocols']}\n"
                )
                self.send_json(200, {
                    "ok": True,
                    "message": (
                        f"Switch {FAULT_SWITCH} misconfigured "
                        "(wrong controller and protocol)"
                        if action == "enable"
                        else f"Switch {FAULT_SWITCH} controller and protocol restored"
                    ),
                    **state,
                })
            except Exception as exc:
                self.send_json(500, {
                    "ok": False,
                    "error": f"Could not change switch configuration: {exc}",
                })
            return

        route_actions = {
            "/api/service": apply_service_fault,
            "/api/process": apply_process_fault,
            "/api/controller": apply_controller_fault,
            "/api/path": apply_path_fault,
        }
        if self.path in route_actions:
            action = self.read_action()
            if action is None:
                return
            try:
                result = route_actions[self.path](action)
                result["ok"] = True
                result["message"] = f"{result['id']} fault {'enabled' if action == 'enable' else 'disabled'}"
                self.send_json(200, result)
            except Exception as exc:
                self.send_json(500, {"ok": False, "error": f"Could not apply {self.path.rsplit('/', 1)[-1]} fault: {exc}"})
            return

        self.send_json(404, {"ok": False, "error": "Not found"})

    def recover_link_request(self):
        """Only a token-authenticated, durably claimed automatic attempt may run."""
        base = Path(__file__).resolve().parent
        try:
            token = (base / "recovery.token").read_text().strip()
            supplied = self.headers.get("X-Recovery-Token", "")
            if not token or not hmac.compare_digest(supplied, token):
                self.send_json(403, {"ok": False, "error": "Authentication failed"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("Object required")
            iid = payload.get("incident_id")
            if not isinstance(iid, str) or not re.fullmatch(r"[a-f0-9]{32}", iid):
                raise ValueError("Invalid incident ID")
            route_policy = {
                "/api/recovery/link": ("link_failure", "restore_link"),
                "/api/recovery/config": ("config_failure", "restore_service_config"),
                "/api/recovery/switch": ("switch_config_failure", "restore_switch_config"),
                "/api/recovery/path": ("path_failure", "restore_path"),
                "/api/recovery/process": ("process_failure", "restart_process"),
                "/api/recovery/service": ("service_stopped", "restart_service"),
                "/api/recovery/controller": ("controller_disconnection", "restore_controller"),
            }
            classification, action = route_policy[self.path]
            db_path = base / "logs" / "recovery_history.sqlite3"
            db = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=5)
            try:
                row = db.execute("SELECT data FROM incidents WHERE id=?", (iid,)).fetchone()
            finally:
                db.close()
            claim = json.loads(row[0]) if row else {}
            if (claim.get("status") != "RECOVERING"
                    or claim.get("classification") != classification
                    or claim.get("action") != action
                    or claim.get("gate_at_execution") is not True
                    or not claim.get("active")
                    or not owner_alive(claim.get("owner", {}))):
                self.send_json(409, {"ok": False, "error": "No live, enabled recovery claim"})
                return
            try:
                permission = execution_permit(base / "logs/recovery_power.json")
                permission.__enter__()
            except PowerDisabled:
                self.send_json(403, {"ok": False, "error": "MAIN POWER is OFF", "code": "POWER_OFF", "action_started": False})
                return
            try:
                if iid not in LINK_RESULTS:
                    try:
                        if action == "restore_link":
                            result = recover_link(network, iid)
                        elif action == "restart_service":
                            result = recover_service(network, service_process_pids, apply_service_fault)
                        elif action == "restore_controller":
                            result = recover_controller(network, ControllerManager(base))
                            if result.get("verified") is True:
                                global controller_is_disconnected
                                controller_is_disconnected = False
                        else:
                            result = recover_classified(action, network, apply_switch_fault, apply_path_fault,
                                                        start_process_worker, read_switch_state, current_edge_states,
                                                        lambda: worker_pids(network), current_controller_health,
                                                        current_service_health)
                        SYSTEM_HEALTH.invalidate()
                        LINK_RESULTS[iid] = result
                    except Exception as exc:
                        # The operation may already have acted; never cache a fabricated success.
                        LINK_RESULTS[iid] = {"ok": False, "verified": False,
                                             "recovery_status": "UNVERIFIED", "failure_reason": str(exc)}
                # 200 transports both success and failure evidence; verified is authoritative.
                self.send_json(200, LINK_RESULTS[iid])
            finally:
                permission.__exit__(None, None, None)
        except (ValueError, TypeError) as exc:
            self.send_json(400, {"ok": False, "error": str(exc)})
        except Exception as exc:
            self.send_json(503, {"ok": False, "error": str(exc)})

    def log_message(self, fmt, *args):
        info("*** Control API: " + (fmt % args) + "\n")


def main():
    global network

    # ACN_HEADLESS_LIFETIME_V1
    # Let SIGTERM follow the same finally-cleanup path as Ctrl+C.
    def terminate_cleanly(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate_cleanly)

    network = Mininet(
        topo=ACNTopology(),
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=True,
        build=False,
    )

    network.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633,
    )

    server = ThreadingHTTPServer((CONTROL_HOST, CONTROL_PORT), ControlHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)

    try:
        info("\n*** Building ACN network: 5 switches, 8 hosts\n")
        network.build()
        network.start()

        initialize_service_config()

        if not service_process_running():
            service_state = apply_service_fault("disable")

            if not service_state["running"]:
                info("*** Warning: health service did not start on h2\n")

        if not start_process_worker():
            info("*** Warning: could not start the process-fault worker\n")

        HEALTH_STOPPED.clear()
        threading.Thread(target=SYSTEM_HEALTH.run,
                         args=(independent_system_health, NETWORK_LOCK, HEALTH_STOPPED),
                         daemon=True).start()
        server_thread.start()
        info(
            f"\n*** Link-control API listening on "
            f"http://{CONTROL_HOST}:{CONTROL_PORT}\n"
        )

        info("\n*** Waiting for network convergence\n")
        time.sleep(30)

        info("\n*** Initial connectivity test\n")
        with NETWORK_LOCK:
            network.pingAll()

        info("\n*** Network ready. Use dashboard link controls or Mininet CLI.\n")
        if sys.stdin.isatty():
            CLI(network)
        else:
            info("\n*** Background mode: keeping Mininet and control API running.\n")
            threading.Event().wait()
    finally:
        HEALTH_STOPPED.set()
        server.shutdown()
        server.server_close()
        network.stop()


if __name__ == "__main__":
    setLogLevel("info")
    main()
