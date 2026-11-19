#!/usr/bin/env python3
"""ACN SDN Fault Detection & Recovery dashboard.

All seven fault injection controls operate on the live Mininet topology or service configuration.
MAIN POWER gates classified recovery; independent probes establish system health.
"""
import json
import hmac
import secrets
from urllib.parse import urlsplit
import power_control
from system_health import build_monitor, fresh
from recovery_engine import RECOVERY_POLICIES
import os
import threading
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

from classify_fault import (
    apply_topology_payload,
    classify_evidence,
    classify_log_record,
    summarize_classifications,
)
from common import DETECTION_STATUS_FILE, read_detection_status

BASE_DIR = Path(__file__).resolve().parent
FAULT_LOG = BASE_DIR / "logs" / "faults.jsonl"
STATUS_FILE = BASE_DIR / "logs" / "service_status.json"
RECOVERY_STATUS_FILE = BASE_DIR / "logs" / "recovery_status.json"
SERVICE_CONFIG = Path("/tmp/service.conf")
HEALTHY_CONFIG = "mode=ok"
FAULTY_CONFIG = "mode=broken"
MININET_API = "http://127.0.0.1:8765"

# RYU_DASHBOARD_CONTROL_V1
RYU_BIN = BASE_DIR / ".ryu39" / "bin" / "ryu-manager"
RYU_LOG = BASE_DIR / "logs" / "ryu.log"
RYU_HOST = "127.0.0.1"
RYU_PORT = 6633
_ryu_process = None
_ryu_lock = threading.Lock()
IMPLEMENTED_FAULTS = ("link", "config", "switch", "service", "process", "controller", "path")
DETECTION_MAX_AGE = 15

POWER_FILE = BASE_DIR / "logs/recovery_power.json"
POWER_NONCE = secrets.token_hex(32)

app = Flask(__name__)
_config_job_lock = threading.Lock()
_config_job_id = 0
_config_pipeline = {
    "detected": False,
    "recovered": False,
    "detail": "No configuration fault has been injected.",
}

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACN | Fault Detection & Recovery</title>
<style>
:root {
  --bg:#0b1020; --panel:#121a2d; --panel2:#172238; --line:#293650;
  --text:#edf3ff; --muted:#9caec8; --green:#42d392; --red:#ff667a;
  --amber:#ffc66d; --blue:#79aaff;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at 15% 0%,#172746 0,var(--bg) 43%);color:var(--text);font:14px/1.45 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
header{padding:22px clamp(16px,4vw,44px);background:#0b1223d9;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:16px}
h1{font-size:clamp(21px,3vw,30px);margin:0;letter-spacing:-.6px}
header p{color:var(--muted);margin:5px 0 0}
.pill{white-space:nowrap;border:1px solid #69552c;background:#342a17;color:var(--amber);padding:7px 10px;border-radius:99px;font-size:16px;font-weight:800;letter-spacing:.7px}
main{max-width:1450px;margin:22px auto;padding:0 18px 35px}
.layout{display:grid;grid-template-columns:minmax(300px,.78fr) minmax(0,1.55fr);gap:16px;align-items:start}
.panel{background:linear-gradient(180deg,rgba(23,34,56,.97),rgba(18,26,45,.98));border:1px solid var(--line);border-radius:16px;overflow:hidden;box-shadow:0 14px 38px #0002}
.panel-head{padding:16px 18px 0;display:flex;justify-content:space-between;align-items:center;gap:10px}
.panel-head h2{font-size:16px;margin:0}
.panel-body{padding:15px 18px 18px}
.muted{color:var(--muted)}
.small{font-size:16px;color:var(--muted)}
.kicker{font-size:16px;text-transform:uppercase;letter-spacing:1.2px;font-weight:800;color:var(--muted)}
button{border:0;cursor:pointer;border-radius:8px;padding:8px 10px;font-weight:800;font-size:16px;transition:filter .15s}
button:hover{filter:brightness(1.12)}
button:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
button:disabled{opacity:.38;cursor:not-allowed}
.enable{background:#1e694d;color:#eafff5}
.disable{background:#432633;border:1px solid #633341;color:#ffc2cb}
.secondary{background:#263650;border:1px solid #3a4d6a;color:#e0eaff}
.ryu-panel{margin-bottom:16px}
.ryu-controls{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.ryu-status{font-weight:900;font-size:16px}
.ryu-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--red);margin-right:7px}
.ryu-dot.on{background:var(--green);box-shadow:0 0 8px #42d39288}
.ryu-info{font-size:16px;color:var(--muted);margin-top:10px}
.fault-list{display:grid;gap:9px}
.fault-item{border:1px solid var(--line);border-radius:11px;padding:11px 12px;background:#080e1c66}
.fault-item.active{border-color:#a63e53;background:#311c2a88}
.fault-item-top{display:flex;align-items:flex-start;gap:9px}
.icon{width:29px;height:29px;border-radius:8px;background:#1b2a44;display:grid;place-items:center;flex-shrink:0;font-size:16px}
.fault-name{font-weight:800;font-size:16px;line-height:1.3}
.fault-desc{font-size:16px;color:var(--muted);margin-top:3px}
.fault-controls{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:9px}
.state{font-size:16px;letter-spacing:.4px;font-weight:900;color:var(--green)}
.state.active{color:var(--red)}
.actions{display:flex;gap:6px}
.actions button{padding:7px 9px}
#clearAll{font-size:16px}
.monitor-hero{padding:20px;border:1px solid var(--line);border-radius:13px;background:#080e1c66;display:flex;gap:15px;align-items:center;margin-bottom:13px}
.big-dot{width:14px;height:14px;border-radius:50%;background:var(--green);box-shadow:0 0 0 6px #42d39218;flex-shrink:0}
.big-dot.bad{background:var(--red);box-shadow:0 0 0 6px #ff667a18}
.hero-title{font-size:clamp(18px,2vw,24px);font-weight:900;letter-spacing:-.5px}
.hero-detail{font-size:16px;color:var(--muted);margin-top:4px}
.badge{margin-left:auto;border-radius:99px;padding:7px 10px;background:#14372d;color:var(--green);font-size:16px;font-weight:900;white-space:nowrap}
.badge.bad{background:#421f2a;color:var(--red)}
.badge.wait{background:#342a17;color:var(--amber)}
.recovery-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:13px}
.metric{padding:13px;border:1px solid var(--line);border-radius:11px;background:#080e1c66;min-width:0}
.metric-label{font-size:16px;color:var(--muted)}
.metric-value{font-size:20px;font-weight:900;margin-top:5px;overflow-wrap:anywhere}
.metric-sub{font-size:16px;color:var(--muted);margin-top:3px}
.detected-box{border:1px solid var(--line);border-radius:12px;padding:14px;margin-top:12px}
.detected-box h3{font-size:16px;margin:0 0 10px}
.detected-list{display:grid;gap:8px}
.detected-row{display:flex;align-items:center;gap:9px;border-radius:9px;padding:10px;background:#311c2a66;border:1px solid #633341}
.detected-row .dot{width:7px;height:7px;background:var(--red);border-radius:50%;flex-shrink:0}
.detected-row strong{font-size:16px}
.detected-row small{display:block;color:var(--muted);font-size:16px;margin-top:2px}
.empty{font-size:16px;color:var(--muted);padding:7px 0}
.progress-steps{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:12px}
.step{border:1px solid var(--line);border-radius:9px;padding:11px 9px;background:#080e1c55}
.step-no{font-size:16px;color:var(--muted);font-weight:900;letter-spacing:.7px}
.step-name{font-size:16px;font-weight:800;margin-top:5px}
.step-state{font-size:16px;color:var(--amber);margin-top:5px;font-weight:800}
.step.done .step-state{color:var(--green)}
.step.active-step{border-color:#69552c}
.lower{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(270px,.8fr);gap:16px;margin-top:16px}
table{width:100%;border-collapse:collapse;min-width:500px}
th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);font-size:16px;vertical-align:top}
th{color:var(--muted);font-size:16px;letter-spacing:.8px;text-transform:uppercase}
.table-wrap{overflow-x:auto}
.tag{display:inline-block;background:#421f2a;color:#ffc2cb;border-radius:99px;padding:4px 7px;font-size:16px;font-weight:900}
.healthy{color:var(--green)}.unhealthy{color:var(--red)}.neutral{color:var(--blue)}
.footnote{font-size:16px;color:var(--muted);margin-top:12px}
@media(max-width:980px){.layout{grid-template-columns:1fr}.fault-list{grid-template-columns:repeat(2,minmax(0,1fr))}.lower{grid-template-columns:1fr}}
@media(max-width:620px){header{align-items:flex-start;flex-direction:column}.fault-list{grid-template-columns:1fr}.recovery-grid{grid-template-columns:1fr}.progress-steps{grid-template-columns:repeat(2,minmax(0,1fr))}.panel-body{padding:13px}.panel-head{padding:14px 13px 0}}

/* ACN_NETWORK_CONTROLS_V1 */
.network-controls{display:flex;gap:9px;flex-wrap:wrap}
.network-controls button{min-width:145px}
.network-status{font-size:16px;color:var(--muted);margin:10px 0}
.network-warning{font-size:16px;color:var(--amber);margin-top:8px}


:root{--bg:#f4f7fc;--panel:#fff;--panel2:#f8faff;--line:#e3eaf4;--text:#17243a;--muted:#718096;--green:#159b62;--red:#dc4b58;--amber:#c78318;--blue:#3478d4}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
.app-shell{min-height:100vh;display:grid;grid-template-columns:225px minmax(0,1fr)}.sidebar{position:sticky;top:0;height:100vh;background:#fff;border-right:1px solid var(--line);padding:22px 14px;display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:11px;padding:4px 9px 28px}.brand-mark{width:39px;height:39px;border-radius:12px;background:#eaf2ff;color:#2467c5;display:grid;place-items:center;font-weight:900}.brand strong{display:block;font-size:16px}.brand small{display:block;color:var(--muted);font-size:16px;margin-top:2px}.side-nav{display:grid;gap:6px}.nav-item{display:flex;align-items:center;gap:12px;text-align:left;background:transparent;color:#53647c;padding:12px 13px;border-radius:10px;font-size:16px;font-weight:700}.nav-item span{width:18px;text-align:center;font-size:16px}.nav-item:hover,.nav-item.active{background:#eaf2ff;color:#2166c3}.sidebar-foot{margin-top:auto;padding:14px 9px 3px;color:#9aa8ba;font-size:16px}
.workspace{min-width:0}.topbar{height:78px;background:#fff;border-bottom:1px solid var(--line);padding:14px 28px;display:flex;align-items:center;justify-content:space-between}.topbar h1{font-size:20px;margin:0}.topbar p{margin:3px 0 0;color:var(--muted);font-size:16px}.top-status{display:flex;align-items:center;gap:8px;color:#21865b;background:#eaf8f1;border-radius:30px;padding:7px 12px;font-size:16px;font-weight:800}.top-status i{width:7px;height:7px;border-radius:50%;background:#19a66a}
main{max-width:1500px;margin:0 auto;padding:24px 28px 40px}.page{display:none}.page.active{display:block}.page-heading{display:flex;align-items:center;justify-content:space-between;margin:0 0 17px}.page-heading h2{font-size:21px;margin:0}.page-heading p{color:var(--muted);font-size:16px;margin:3px 0 0}.source-chip{background:#edf4ff;color:#326fc0;border-radius:20px;padding:7px 11px;font-size:16px;font-weight:800}
.panel{background:#fff;border:1px solid var(--line);border-radius:14px;box-shadow:0 4px 16px #243b5a0a;overflow:hidden}.panel-head{padding:16px 19px 0}.panel-head h2{font-size:16px}.panel-body{padding:16px 19px 19px}.muted,.small,.footnote,.kicker{color:var(--muted)}.layout{grid-template-columns:1fr}.lower{grid-template-columns:1fr}.fault-list{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.fault-item{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px}.fault-item.active{border-color:#f0b4ba;background:#fff8f8}.icon{background:#edf4ff;color:#3478d4}.enable{background:#168e5c;color:#fff}.disable{background:#fff0f1;border:1px solid #f3c9cd;color:#c43e4b}.secondary{background:#edf3fb;border:1px solid #dce6f2;color:#435875}.monitor-hero{background:#f7faff;border:1px solid var(--line)}.metric,.detected-box,.step{background:#fff;border:1px solid var(--line)}.detected-row{background:#fff5f5;border:1px solid #f3d4d7}.badge{background:#eaf8f1;color:#168657}.badge.bad{background:#fff0f1;color:#c43e4b}.badge.wait{background:#fff7e8;color:#a56b12}.step.active-step{border-color:#bdd4f4;background:#f7faff}.step.done .step-state{color:#168657}th,td{border-bottom:1px solid var(--line)}th{color:#74839a}.tag{background:#edf4ff;color:#326fc0}.healthy{color:#168657}.unhealthy{color:#c43e4b}.neutral{color:#3478d4}
.topology-legend{display:flex;gap:22px;flex-wrap:wrap;color:#66768d;font-size:16px;margin-bottom:12px}.topology-legend span{display:flex;align-items:center;gap:7px}.topology-legend i{display:inline-block;width:12px;height:12px}.switch-key{background:#2f78d2;border-radius:3px}.host-key{background:#fff;border:2px solid #6b829f;border-radius:3px}.link-key{height:2px!important;background:#9aabc0}.topology-canvas{width:100%;overflow:auto;background:#fbfdff;border:1px solid #e9eff7;border-radius:12px;padding:10px}.topology-canvas svg{display:block;width:100%;min-width:650px;height:auto}.edges path{fill:none;stroke:#9aabc0;stroke-width:4;stroke-linecap:round}.switch-node rect{fill:#2f78d2;stroke:#1e63b7;stroke-width:2}.host-node rect{fill:#fff;stroke:#6f849e;stroke-width:3}.node-label text{text-anchor:middle;font-size:19px;font-weight:800;fill:#fff}.host-label text{fill:#40546d;font-size:17px}.topology-note{font-size:16px;color:var(--muted);margin-top:12px}
@media(max-width:850px){.app-shell{grid-template-columns:76px minmax(0,1fr)}.sidebar{padding:18px 9px}.brand{justify-content:center;padding:4px 0 25px}.brand>div:last-child,.sidebar-foot{display:none}.nav-item{justify-content:center;padding:12px 8px;font-size:0}.nav-item span{font-size:18px}.topbar{padding:12px 18px}main{padding:20px 16px}}
@media(max-width:620px){.app-shell{grid-template-columns:1fr}.sidebar{position:sticky;z-index:5;top:0;height:auto;padding:8px;background:#fff;border-right:0;border-bottom:1px solid var(--line)}.brand{display:none}.side-nav{display:flex;overflow-x:auto;gap:4px}.nav-item{white-space:nowrap;padding:9px 11px;font-size:16px}.topbar{height:auto;min-height:68px}.topbar h1{font-size:16px}.top-status{font-size:0;padding:9px}.fault-list{grid-template-columns:1fr}.recovery-grid{grid-template-columns:1fr}.progress-steps{grid-template-columns:repeat(2,minmax(0,1fr))}}


/* ACN SIMPLE READABILITY + THEME CONTROLS */
body{font-size:16px;line-height:1.55}
.sidebar{width:auto}
.brand strong{font-size:17px}.brand small{font-size:16px}
.nav-item{font-size:16px;padding:13px 14px}
.topbar h1{font-size:25px}.topbar p{font-size:16px}
main{padding:28px 32px 44px}
.page-heading h2{font-size:25px}.page-heading p{font-size:16px}
.panel-head h2{font-size:19px}.panel-body{font-size:16px}
.kicker{font-size:16px}.small,.footnote,.topology-note{font-size:16px}
button{font-size:16px;padding:10px 14px}
.fault-name{font-size:16px}.fault-desc{font-size:16px}
.state{font-size:16px}.actions button{font-size:16px;padding:9px 12px}
.ryu-status{font-size:16px}.ryu-info,.network-status{font-size:16px}
.hero-title{font-size:25px}.hero-detail{font-size:16px}
.badge,.top-status,.source-chip{font-size:16px}
.metric-label{font-size:16px}.metric-value{font-size:24px}.metric-sub{font-size:16px}
.detected-box h3{font-size:16px}.detected-row strong{font-size:16px}
.detected-row small{font-size:16px}.empty{font-size:16px}
.step-no{font-size:16px}.step-name{font-size:16px}.step-state{font-size:16px}
th,td{font-size:16px;padding:12px}th{font-size:16px}.tag{font-size:16px}
.theme-controls{display:flex;gap:10px;flex-wrap:wrap}
.theme-choice{min-width:125px}
.theme-choice.active{background:#2468c7;color:#fff;border-color:#2468c7}
body[data-theme="dark"]{background:#0c1424;color:#edf3ff}
body[data-theme="dark"] .sidebar,
body[data-theme="dark"] .topbar,
body[data-theme="dark"] .panel,
body[data-theme="dark"] .fault-item,
body[data-theme="dark"] .metric,
body[data-theme="dark"] .detected-box,
body[data-theme="dark"] .step{background:#172338;color:#edf3ff;border-color:#30415d}
body[data-theme="dark"] .sidebar{border-right-color:#30415d}
body[data-theme="dark"] .topbar{border-bottom-color:#30415d}
body[data-theme="dark"] .nav-item{color:#c0cce0}
body[data-theme="dark"] .nav-item:hover,
body[data-theme="dark"] .nav-item.active{background:#263c5e;color:#fff}
body[data-theme="dark"] .monitor-hero,
body[data-theme="dark"] .topology-canvas{background:#111d30;border-color:#30415d}
body[data-theme="dark"] .topology-canvas svg{filter:brightness(1.08)}
body[data-theme="dark"] .host-node rect{fill:#172338}
body[data-theme="dark"] .host-label text{fill:#e1eaf8}
body[data-theme="dark"] .detected-row{background:#38232e;border-color:#70404d}
body[data-theme="dark"] .secondary{background:#263c5e;color:#e7efff;border-color:#405779}
body[data-theme="dark"] th,body[data-theme="dark"] td{border-bottom-color:#30415d}
body[data-theme="dark"] .muted,
body[data-theme="dark"] .small,
body[data-theme="dark"] .footnote,
body[data-theme="dark"] .kicker,
body[data-theme="dark"] .metric-label,
body[data-theme="dark"] .metric-sub{color:#b4c2d8}
@media(max-width:620px){
  main{padding:18px 14px 30px}
  .page-heading h2{font-size:22px}
  .panel-head h2{font-size:17px}
  .nav-item{font-size:16px}
}

.power-panel{margin-bottom:20px;border:2px solid #8aa6c7}.power-row{display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap}.main-power{font-size:21px;font-weight:800;letter-spacing:.5px;padding:20px 30px;min-width:265px;border-radius:13px;background:#334155;color:white;border:2px solid #64748b;cursor:pointer}.main-power.on{background:#087c51;border-color:#059669}.main-power.stopping{background:#975a08}.main-power:disabled{cursor:wait;opacity:.7}.power-detail{max-width:650px;font-size:16px;line-height:1.6}.power-error{color:#c43e4b;white-space:pre-wrap}.power-note{font-size:16px;color:var(--muted);margin-top:12px}.progress-steps{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))}
/* ACN_READABLE_UI_V2: readable defaults; preserve one primary power control. */
body{font-size:18px;line-height:1.55}button,input,select,textarea{font:inherit}button{font-size:18px;min-height:48px;padding:12px 18px}small,.small,.footnote,.kicker,.power-note,.metric-sub,.metric-label,.badge,.tag,.step-no,.topology-note,.sidebar-foot{font-size:16px;line-height:1.5}.nav-item{font-size:18px}.hero-title{font-size:28px}.hero-detail,.power-detail,.step-state,.step-name{font-size:18px;line-height:1.5}.metric-value{font-size:30px}.panel-head h2,.detected-box h3{font-size:21px}.main-power{font-size:24px;min-width:320px;min-height:80px;padding:22px 28px}.advanced-controls{border:1px solid var(--line);border-radius:12px;margin:18px 0;padding:14px}.advanced-controls>summary{font-size:18px;font-weight:700;cursor:pointer;padding:8px}.advanced-controls .panel{margin-top:14px}p:empty,.footnote:empty{display:none}.power-row>div{flex:1;min-width:250px}.step-state{overflow-wrap:anywhere}svg text{font-size:18px}th,td{font-size:16px;padding:14px 12px}@media(max-width:760px){.fault-list,.recovery-grid,.progress-steps{grid-template-columns:1fr}.main-power{width:100%;min-width:0}.power-row{gap:14px}.hero-title{font-size:24px}.topbar h1{font-size:24px}}
</style>
</head>
<body>
<div class="app-shell">
 <aside class="sidebar">
  <div class="brand"><div class="brand-mark">ACN</div><div><strong>ACN Network</strong><small>Fault Recovery</small></div></div>
  <nav class="side-nav" aria-label="Main navigation">
   <button class="nav-item active" data-page="dashboard"><span>▦</span>Dashboard</button>
   <button class="nav-item" data-page="topology"><span>⌘</span>Topology</button>
   <button class="nav-item" data-page="faults"><span>⚡</span>Fault Injection</button>
   <button class="nav-item" data-page="logs"><span>▤</span>Logs</button>
   <button class="nav-item" data-page="settings"><span>⚙</span>Settings</button>
  </nav>
  <div class="sidebar-foot">ACN · SDN Prototype</div>
 </aside>
 <div class="workspace">
  <header class="topbar"><div><h1>Fault Detection &amp; Recovery</h1><p></p></div><span class="top-status"><i></i> Live Monitor</span></header>
  <main>
   <section class="page active" id="page-dashboard">
    <div class="page-heading"><div><h2>Dashboard</h2><p></p></div></div>
    <section class="panel power-panel" aria-label="Recovery main power">
     <div class="panel-body"><div class="power-row"><div>
      <h2>Automatic Recovery · MAIN POWER</h2>
      <p id="powerDetail" class="power-detail" aria-live="polite">Reading the shared backend gate…</p>
      <p id="powerAck" class="power-note"></p>
     </div><button type="button" id="mainPower" class="main-power" disabled aria-pressed="false">⏻ MAIN POWER · CHECKING</button></div>
     <p class="power-note">OFF observes and classifies only. ON permits automatic recovery and verification. Accepted actions finish safely before OFF; manual controls are separate.</p>
     <div id="powerError" class="power-error" role="alert"></div></div>
    </section>

    <section class="panel">
      <div class="panel-head"><h2>Recovery System Health Monitor</h2><span class="kicker">Primary monitor</span></div>
      <div class="panel-body">
        <div class="monitor-hero">
          <span id="heroDot" class="big-dot"></span>
          <div style="min-width:0"><div id="heroTitle" class="hero-title">Awaiting Independent Verification</div><div id="heroDetail" class="hero-detail">Fresh network and service checks are required before HEALTHY.</div></div>
          <span id="heroBadge" class="badge wait">UNKNOWN</span>
        </div>
        <div class="recovery-grid">
          <div class="metric"><div class="metric-label">Real service health · h2:8080</div><div class="metric-value neutral" id="realHealth">Checking…</div><div class="metric-sub">Current detector service-health snapshot</div></div>
          <div class="metric"><div class="metric-label">Detected / classified</div><div class="metric-value" id="activeCount">0 / 7</div><div class="metric-sub" id="detectionSub">Observed evidence, not Enable-button state</div></div>
          <div class="metric"><div class="metric-label">Latest recovery status</div><div class="metric-value neutral" id="recoveryStatus">Checking…</div><div class="metric-sub" id="recoveryDetail">Loading actual service status</div></div>
        </div>

        <div class="detected-box">
          <h3>Detected Faults <span class="small" id="detectedSummary">(0 active)</span></h3>
          <div id="detectedList" class="detected-list"><div class="empty">No observed faults. Injection alone is not treated as detection.</div></div>
        </div>

        <div class="detected-box">
          <h3>Recovery Workflow</h3>
          <div class="progress-steps">
            <div class="step active-step" id="step1"><div class="step-no">STEP 01</div><div class="step-name">Fault Detection</div><div class="step-state" id="step1state">STANDBY</div></div>
            <div class="step" id="step2"><div class="step-no">STEP 02</div><div class="step-name">Classification</div><div class="step-state" id="step2state">WAITING</div></div>
            <div class="step" id="step3"><div class="step-no">STEP 03</div><div class="step-name">Recovery Engine</div><div class="step-state" id="step3state">NOT CONNECTED</div></div>
            <div class="step" id="step4"><div class="step-no">STEP 04</div><div class="step-name">Verification</div><div class="step-state" id="step4state">UNKNOWN</div></div>
            <div class="step" id="step5"><div class="step-no">OVERALL</div><div class="step-name">System Health</div><div class="step-state" id="step5state">UNKNOWN</div></div>
          </div>
          <p class="footnote"></p>
        </div>
      </div>
    </section>
   </section>
   <section class="page" id="page-topology">
    <div class="page-heading"><div><h2>Network Topology</h2><p>5 switches · 8 hosts</p></div><span class="source-chip">topo_large.py</span></div>
    <section class="panel topology-panel"><div class="panel-head"><h2>Mininet Network Map</h2></div><div class="panel-body">
     <div class="topology-legend"><span><i class="switch-key"></i>Switch</span><span><i class="host-key"></i>Host</span><span><i class="link-key"></i>Link</span></div>
     <div class="topology-canvas"><svg viewBox="0 0 1000 500" role="img" aria-label="Five switches and eight hosts from the ACN Mininet topology">
      <g class="edges"><path d="M120 130 L320 130"/><path d="M320 130 L520 130"/><path d="M320 130 L720 130"/><path d="M520 130 L900 130"/><path d="M720 130 L900 130"/><path d="M120 130 L80 285"/><path d="M320 130 L185 375"/><path d="M520 130 L320 285"/><path d="M120 130 L420 375"/><path d="M720 130 L520 285"/><path d="M900 130 L620 375"/><path d="M720 130 L720 285"/><path d="M900 130 L820 375"/></g>
      <g class="switch-node"><rect x="75" y="95" width="90" height="66" rx="12"/><rect x="275" y="95" width="90" height="66" rx="12"/><rect x="475" y="95" width="90" height="66" rx="12"/><rect x="675" y="95" width="90" height="66" rx="12"/><rect x="855" y="95" width="90" height="66" rx="12"/></g>
      <g class="node-label switch-label"><text x="120" y="136">s1</text><text x="320" y="136">s2</text><text x="520" y="136">s3</text><text x="720" y="136">s4</text><text x="900" y="136">s5</text></g>
      <g class="host-node"><rect x="50" y="285" width="60" height="42" rx="8"/><rect x="155" y="375" width="60" height="42" rx="8"/><rect x="290" y="285" width="60" height="42" rx="8"/><rect x="390" y="375" width="60" height="42" rx="8"/><rect x="490" y="285" width="60" height="42" rx="8"/><rect x="590" y="375" width="60" height="42" rx="8"/><rect x="690" y="285" width="60" height="42" rx="8"/><rect x="790" y="375" width="60" height="42" rx="8"/></g>
      <g class="node-label host-label"><text x="80" y="312">h1</text><text x="185" y="402">h2</text><text x="320" y="312">h3</text><text x="420" y="402">h4</text><text x="520" y="312">h5</text><text x="620" y="402">h6</text><text x="720" y="312">h7</text><text x="820" y="402">h8</text></g>
     </svg></div><p class="topology-note">Switches and host connections are drawn from the 5-switch, 8-host topology definition.</p>
    </div></section>
   </section>
   <section class="page" id="page-faults">
    <div class="page-heading"><div><h2>Fault Injection</h2><p>Manual fault controls are available below.</p></div></div>
    <details class="advanced-controls">
     <summary>Advanced manual controls · Fault Injection</summary>
     <section class="panel">
      <div class="panel-head"><h2>Fault Injecting</h2><button class="secondary" id="clearAll">Disable All</button></div>
      <div class="panel-body">
        <p class="small" style="margin-top:0"></p>
        <div class="fault-list" id="faultList"></div>
        <p class="footnote">Enable injects a real fault. Disable restores the corresponding service, link, or switch configuration.</p>
      </div>
     </section>
    </details>
   </section>
   <section class="page" id="page-logs"><div class="page-heading"><div><h2>Logs</h2><p>Fault history</p></div></div><section class="panel">
      <div class="panel-head"><h2>Real Fault History</h2><span class="kicker">logs/faults.jsonl</span></div>
      <div class="panel-body">
        <div class="table-wrap"><table><thead><tr><th>Detected at (UTC)</th><th>Type</th><th>Classification</th><th>Target</th><th>Details</th></tr></thead><tbody id="faults"><tr><td colspan="5">Loading fault history…</td></tr></tbody></table></div>
      </div>
    </section></section>
   <section class="page" id="page-settings"><div class="page-heading"><div><h2>Settings</h2><p>Basic system information</p></div></div><section class="panel">
      <div class="panel-head"><h2>System Summary</h2><span class="kicker">Live + demo</span></div>
      <div class="panel-body">
        <div class="metric" style="margin-bottom:14px">
          <div class="metric-label" style="font-size:16px;margin-bottom:10px">Appearance</div>
          <div class="theme-controls">
            <button type="button" class="secondary theme-choice active" data-theme-choice="light">Light mode</button>
            <button type="button" class="secondary theme-choice" data-theme-choice="dark">Dark mode</button>
          </div>
        </div>
        <div class="metric" style="margin-bottom:9px"><div class="metric-label">Total recorded faults (real log)</div><div class="metric-value" id="totalRealFaults">—</div></div>
        <div class="metric"><div class="metric-label">Last real fault recorded</div><div class="metric-value" style="font-size:16px" id="latestRealFault">—</div></div>
        <p class="footnote"></p>
      </div>
    </section></section>
  </main>
 </div>
</div>
<script>document.querySelectorAll(".nav-item").forEach(button=>button.addEventListener("click",()=>{document.querySelectorAll(".nav-item").forEach(item=>item.classList.toggle("active",item===button));document.querySelectorAll(".page").forEach(page=>page.classList.toggle("active",page.id===`page-${button.dataset.page}`));}));</script>
<script>
const scenarios = [
 {id:"config",icon:"⚙",name:"Service Configuration Failure",desc:"Invalid health-service configuration."},
 {id:"switch",icon:"⇄",name:"Switch Configuration Failure",desc:"Incorrect controller target or protocol on s4."},
 {id:"link",icon:"↯",name:"Network Link Failure",desc:"A Mininet network link is down."},
 {id:"service",icon:"♥",name:"Health Service Stopped",desc:"HTTP health service is unavailable."},
 {id:"process",icon:"▣",name:"Process Failure",desc:"A monitored process has stopped."},
 {id:"controller",icon:"⌘",name:"Controller Disconnection",desc:"Switch is disconnected from Ryu."},
 {id:"path",icon:"⇢",name:"Network Path Failure",desc:"Active path failed; alternate path may be needed."}
];
const active = new Set();

const faultList = document.getElementById("faultList");
const esc = s => String(s ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function renderFaultControls(){
 faultList.innerHTML = scenarios.map(s=>{
  const on=active.has(s.id);
  return `<article class="fault-item ${on?"active":""}">
   <div class="fault-item-top"><div class="icon">${s.icon}</div><div><div class="fault-name">${s.name}</div><div class="fault-desc">${s.desc}</div></div></div>
   <div class="fault-controls"><span class="state ${on?"active":""}">${on?"● INJECTED":"● NORMAL"}</span>
    <div class="actions"><button class="enable" data-action="enable" data-id="${s.id}" ${on?"disabled":""}>Enable</button><button class="disable" data-action="disable" data-id="${s.id}" ${!on?"disabled":""}>Disable</button></div>
   </div></article>`;
 }).join("");
}
let detectionView = {status:"idle", engine:"unavailable", active:[], detected_count:0, classified_count:0, service_healthy:null};

let powerView = null, systemView = null, powerBusy = false;
const powerCsrf = "__ACN_POWER_NONCE__";
function renderPowerMonitor(){
 const state=systemView && systemView.overall || "UNKNOWN";
 const good=state==="HEALTHY", bad=state==="UNHEALTHY";
 document.getElementById("heroTitle").textContent=good?"System Healthy":state==="RECOVERING"?"Recovery in Progress":bad?"System Unhealthy":"Awaiting Independent Verification";
 document.getElementById("heroBadge").textContent=state;
 document.getElementById("heroBadge").className="badge"+(good?"":bad?" bad":" wait");
 document.getElementById("heroDot").className="big-dot"+(bad?" bad":"");
 document.getElementById("heroDetail").textContent=systemView && systemView.detail || "Fresh independent checks are unavailable. No healthy state is inferred.";
 const stages=systemView && systemView.stages || {detection:"UNKNOWN",classification:"UNKNOWN",execution:"UNKNOWN",verification:"UNKNOWN"};
 [stages.detection,stages.classification,stages.execution,stages.verification,state].forEach((value,index)=>{
  document.getElementById("step"+(index+1)+"state").textContent=value;
  document.getElementById("step"+(index+1)).className="step"+(value==="VERIFIED"||value==="LIVE"||value==="HEALTHY"?" done":" active-step");
 });
 const button=document.getElementById("mainPower");
 const power=powerView && powerView.state || "UNKNOWN";
 button.textContent="⏻ MAIN POWER · "+power;
 button.className="main-power"+(power==="ON"?" on":power==="STOPPING"?" stopping":"");
 button.disabled=powerBusy || !powerView || power==="STOPPING";
 button.setAttribute("aria-pressed",String(Boolean(powerView && powerView.enabled)));
 button.title=power==="ON"?"Turn automatic recovery OFF":"Turn automatic recovery ON";
 document.getElementById("powerDetail").textContent=powerView && powerView.detail || "Gate status is unknown; refresh before changing power.";
 document.getElementById("powerAck").textContent=powerView && powerView.detector_acknowledged?
  "Detector acknowledged power revision "+powerView.revision+" · monitoring remains active":
  "Waiting for a fresh detector acknowledgement. Missing/stale data is never treated as healthy.";
}
async function changeMainPower(){
 if(powerBusy || !powerView)return;
 powerBusy=true;document.getElementById("powerError").textContent="";renderPowerMonitor();
 try{
  const response=await fetch("/api/power",{method:"POST",headers:{"Content-Type":"application/json","X-Power-CSRF":powerCsrf},
   body:JSON.stringify({enabled:!powerView.enabled,expected_revision:powerView.revision})});
  const data=await response.json();
  if(!response.ok || !data.ok)throw new Error(data.error||"Power update rejected");
  powerView=data.power;renderPowerMonitor();await refreshRealStatus();
 }catch(error){document.getElementById("powerError").textContent=error.message;}
 finally{powerBusy=false;renderPowerMonitor();}
}
document.getElementById("mainPower").addEventListener("click",changeMainPower);

function renderMonitor(){
 const injected=active.size;
 const detected=Array.isArray(detectionView.active)?detectionView.active:[];
 const detectedCount=Number(detectionView.detected_count||detected.length||0);
 const classifiedCount=Number(detectionView.classified_count||0);
 const hasDetection=detectedCount>0;
 const serviceHealthy=detectionView.service_healthy;
 document.getElementById("activeCount").textContent=`${detectedCount} / 7`;
 document.getElementById("detectionSub").textContent=classifiedCount
  ?`${classifiedCount} classified · ${injected} injected`
  :`${injected} injected · evidence-based detection`;
 if(hasDetection){
  document.getElementById("heroTitle").textContent="Fault Detected";
  document.getElementById("heroDetail").textContent=`${detectedCount} observed fault${detectedCount===1?"":"s"} classified from detector evidence.`;
  document.getElementById("heroDot").className="big-dot bad";
  document.getElementById("heroBadge").textContent="FAULT DETECTED";
  document.getElementById("heroBadge").className="badge bad";
 }else if(injected){
  document.getElementById("heroTitle").textContent="Injection Active";
  document.getElementById("heroDetail").textContent=`${injected} live injection${injected===1?" is":"s are"} enabled. Waiting for detector evidence; this is not a detection.`;
  document.getElementById("heroDot").className="big-dot";
  document.getElementById("heroBadge").textContent="NOT DETECTED";
  document.getElementById("heroBadge").className="badge wait";
 }else{
  document.getElementById("heroTitle").textContent="Detection Idle";
  document.getElementById("heroDetail").textContent=detectionView.detail||"No confirmed detections. Healthy idle is shown only when health checks support it.";
  document.getElementById("heroDot").className="big-dot";
  document.getElementById("heroBadge").textContent="STANDBY";
  document.getElementById("heroBadge").className="badge wait";
 }
 document.getElementById("detectedSummary").textContent=`(${detectedCount} detected)`;
 const list=document.getElementById("detectedList");
 if(!hasDetection){
  list.innerHTML='<div class="empty">No observed faults. An injected scenario is listed here only after evidence is detected and classified.</div>';
 }else{
  list.innerHTML=detected.map(item=>{
   const label=esc(item.classification||item.fault_type||"unclassified");
   const target=esc(item.target||"unknown");
   const when=esc(item.detected_at||"");
   const why=esc(item.explanation||item.detail||"");
   const badge=item.classification && item.classification!=="unclassified"?"CLASSIFIED":"UNCLASSIFIED";
   const badgeClass=badge==="CLASSIFIED"?"badge bad":"badge wait";
   return `<div class="detected-row"><span class="dot"></span><div><strong>${label}</strong><small>${target} · ${when}<br>${why}</small></div><span class="${badgeClass}">${badge}</span></div>`;
  }).join("");
 }
 document.getElementById("step1state").textContent=hasDetection?"DETECTED":"STANDBY";
 document.getElementById("step2state").textContent=classifiedCount?"CLASSIFIED":(hasDetection?"UNCLASSIFIED":"WAITING");
 document.getElementById("step1").className="step"+(hasDetection?" done":" active-step");
 document.getElementById("step2").className="step"+(classifiedCount?" done":(hasDetection?" active-step":""));
 renderPowerMonitor();
}

let operationBusy = false;

async function controlFault(action, id) {
    if (operationBusy) return;
    operationBusy = true;
    renderFaultControls();

    try {
        const response = await fetch("/api/fault", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({action, id})
        });

        const result = await response.json();

        if (!response.ok || !result.ok) {
            throw new Error(result.error || "Fault operation failed");
        }

        if (action === "enable") active.add(id);
        else active.delete(id);

        renderFaultControls();
        renderMonitor();

        document.getElementById("heroDetail").textContent =
            result.message || "Operation completed.";

        await refreshLiveFaultStatus();
        await refreshRealStatus();
    } catch (error) {
        alert("Could not perform operation: " + error.message);
    } finally {
        operationBusy = false;
        renderFaultControls();
    }
}

async function applyStatus(url, onState) {
    try {
        const response = await fetch(url, {cache: "no-store"});
        const data = await response.json();
        if (response.ok && data.ok) onState(data);
    } catch (error) {
        console.warn("Could not refresh fault state:", url, error);
    }
}

async function refreshLiveFaultStatus() {
    await applyStatus("/api/link/status", data => {
        if (data.state === "down") active.add("link");
        else active.delete("link");
    });
    await applyStatus("/api/config/status", data => {
        if (data.state === "fault") active.add("config");
        else active.delete("config");
    });
    await applyStatus("/api/switch/status", data => {
        if (data.state === "fault") active.add("switch");
        else active.delete("switch");
    });
    for (const id of ["service", "process", "controller", "path"]) {
        await applyStatus(`/api/${id}/status`, data => {
            if (data.state === "fault") active.add(id);
            else active.delete(id);
        });
    }
    renderFaultControls();
    renderMonitor();
}

faultList.addEventListener("click", async e => {
    const button = e.target.closest("button[data-action]");
    if (!button) return;

    const id = button.dataset.id;
    const action = button.dataset.action;

    await controlFault(action, id);
});

document.getElementById("clearAll").addEventListener("click", async () => {
    for (const id of ["link", "config", "switch", "service", "process", "controller", "path"]) {
        if (active.has(id)) await controlFault("disable", id);
    }
});

async function refreshRealStatus(){
 try{
  const r=await fetch("/api/status",{cache:"no-store"});if(!r.ok)throw new Error("API "+r.status);
  const d=await r.json();
  powerView=d.power||null;systemView=d.system_health||null;
  const health=document.getElementById("realHealth");
  health.textContent=d.service.healthy?"HEALTHY":"UNHEALTHY";
  health.className="metric-value "+(d.service.healthy?"healthy":"unhealthy");
  document.getElementById("recoveryStatus").textContent=d.recovery.status;
  document.getElementById("recoveryStatus").className="metric-value "+(d.recovery.status==="HEALTHY"||d.recovery.status==="SUCCESS"?"healthy":"neutral");
  const autoRecovery = d.automatic_recovery && d.automatic_recovery.enabled;
  document.getElementById("recoveryDetail").textContent =
    "Automatic recovery: " + (autoRecovery ? "ENABLED" : "DISABLED") +
    ". " + d.recovery.detail;

  // Render real recovery-engine and verification results.
  const attempts = (d.recovery && Array.isArray(d.recovery.attempts))
      ? d.recovery.attempts : [];
  const latest = attempts.length ? attempts[attempts.length - 1] : null;

  const recoveryState = latest
      ? String(latest.status || "UNKNOWN").toUpperCase()
      : "WAITING";

  const verified = Boolean(latest && latest.verified);

  document.getElementById("step3state").textContent =
      latest ? recoveryState : (autoRecovery ? "READY" : "DISABLED");

  document.getElementById("step4state").textContent =
      verified ? "VERIFIED" :
      latest ? "NOT VERIFIED" : "NOT RUN";

  document.getElementById("step3").className =
      "step" + (latest && recoveryState === "SUCCESS" ? " done" :
      latest ? " active-step" : "");

  document.getElementById("step4").className =
      "step" + (verified ? " done" :
      latest ? " active-step" : "");

  detectionView=Object.assign({active:[],detected_count:0,classified_count:0}, d.detection||{});
  detectionView.service_healthy=d.service && d.service.healthy;
  renderMonitor();
  document.getElementById("totalRealFaults").textContent=d.faults.length;
  document.getElementById("latestRealFault").textContent=d.faults.length?(d.faults[d.faults.length-1].classification||d.faults[d.faults.length-1].fault_type||"Unknown"):"No faults recorded";
  const body=document.getElementById("faults");body.replaceChildren();
  if(!d.faults.length){const row=body.insertRow();const c=row.insertCell();c.colSpan=5;c.textContent="No real faults recorded.";}
  else [...d.faults].reverse().forEach(f=>{
   const row=body.insertRow();
   [f.detected_at||"Unknown",f.fault_type||"Unknown",f.classification||"",f.target||"Unknown",f.explanation||f.detail||""].forEach((v,i)=>{
    const c=row.insertCell();c.textContent=v;
    if(i===1||i===2){const tag=document.createElement("span");tag.className="tag";tag.textContent=v||"n/a";c.replaceChildren(tag);}
   });
  });
 }catch(err){
  powerView=null;systemView=null;renderPowerMonitor();
  const h=document.getElementById("realHealth");h.textContent="CONNECTION ERROR";h.className="metric-value unhealthy";
  document.getElementById("recoveryStatus").textContent="UNKNOWN";
  document.getElementById("recoveryDetail").textContent="Could not read real status: "+err.message;
 }
}
renderFaultControls();renderMonitor();refreshRealStatus();refreshLiveFaultStatus();
setInterval(refreshRealStatus,2000);
setInterval(refreshLiveFaultStatus,4000);
</script>

<script>
(function(){
  const saved = localStorage.getItem("acn-dashboard-theme") || "light";
  function setTheme(theme){
    document.body.dataset.theme = theme;
    localStorage.setItem("acn-dashboard-theme", theme);
    document.querySelectorAll("[data-theme-choice]").forEach(button=>{
      button.classList.toggle("active", button.dataset.themeChoice === theme);
    });
  }
  document.querySelectorAll("[data-theme-choice]").forEach(button=>{
    button.addEventListener("click", ()=>setTheme(button.dataset.themeChoice));
  });
  setTheme(saved);
})();
</script>

</body>
</html>
"""

def read_faults():
    records = []
    if not FAULT_LOG.exists():
        return records
    try:
        with FAULT_LOG.open("r", encoding="utf-8") as log_file:
            for line in log_file:
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        records.append(classify_log_record(record))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return records


def _parse_checked_at(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


def snapshot_age_seconds(snapshot):
    if not isinstance(snapshot, dict):
        return None
    checked = _parse_checked_at(snapshot.get("checked_at"))
    if checked is None:
        return None
    return (datetime.now(timezone.utc) - checked.astimezone(timezone.utc)).total_seconds()


def collect_live_evidence():
    evidence = {
        "health_unhealthy": False,
        "health_fresh": False,
        "service_config": None,
    }
    try:
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        checked = _parse_checked_at(data.get("checked_at"))
        if checked is not None:
            age = (datetime.now(timezone.utc) - checked.astimezone(timezone.utc)).total_seconds()
            evidence["health_fresh"] = age <= 10
            evidence["health_unhealthy"] = evidence["health_fresh"] and not bool(data.get("healthy"))
    except (OSError, ValueError, json.JSONDecodeError, TypeError, AttributeError):
        pass
    try:
        evidence["service_config"] = read_service_config()
    except OSError:
        evidence["service_config"] = None

    observe, code = proxy_mininet("/api/observe", timeout=2)
    observe_ok = isinstance(observe, dict) and observe.get("ok") and code == 200
    if observe_ok:
        apply_topology_payload(evidence, observe)
        return evidence, True

    fallback_ok = False
    for path in (
        "/api/switch/status",
        "/api/controller/status",
        "/api/service/status",
        "/api/process/status",
    ):
        payload, status_code = proxy_mininet(path, timeout=2)
        if status_code == 200 and isinstance(payload, dict) and payload.get("ok"):
            apply_topology_payload(evidence, payload)
            fallback_ok = True
    return evidence, fallback_ok


def build_detection_payload():
    snapshot = read_detection_status()
    age = snapshot_age_seconds(snapshot) if snapshot else None
    if snapshot and age is not None and age <= DETECTION_MAX_AGE:
        active = snapshot.get("active") if isinstance(snapshot.get("active"), list) else []
        summary = summarize_classifications(active)
        status = "detected" if summary["detected_count"] else "idle"
        if not summary["detected_count"] and check_service():
            status = "healthy"
        return {
            "automatic_recovery_enabled": snapshot.get("automatic_recovery_enabled"),
            "power_revision": snapshot.get("power_revision"),
            "observe_error": snapshot.get("observe_error", False),
            "engine": snapshot.get("engine") or "detect_service",
            "status": status,
            "checked_at": snapshot.get("checked_at"),
            "observe_available": bool(snapshot.get("observe_available")),
            "active": active,
            "detected_count": summary["detected_count"],
            "classified_count": summary["classified_count"],
            "detail": (
                "Detector snapshot is current."
                if summary["detected_count"]
                else "Detector snapshot is current and reports no active incidents."
            ),
            "source": str(DETECTION_STATUS_FILE),
        }

    evidence, observe_ok = collect_live_evidence()
    active = classify_evidence(evidence)
    summary = summarize_classifications(active)
    engine = "live_eval" if observe_ok or evidence.get("health_fresh") else "unavailable"
    if summary["detected_count"]:
        status = "detected"
        detail = "Classified from live evidence because the detector snapshot is missing or stale."
    elif check_service():
        status = "healthy"
        detail = "No observed faults. Service health is fresh and healthy."
    else:
        status = "idle"
        detail = (
            "No confirmed detections. Health status is stale or unavailable, "
            "so a healthy baseline is not claimed."
        )
    return {
        "engine": engine,
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "observe_available": observe_ok,
        "active": active,
        "detected_count": summary["detected_count"],
        "classified_count": summary["classified_count"],
        "detail": detail,
        "source": "live_eval",
    }


def check_service():
    try:
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        checked_at = datetime.fromisoformat(data["checked_at"])
        age = (datetime.now(checked_at.tzinfo) - checked_at).total_seconds()
        return bool(data["healthy"]) and age <= 10
    except (OSError, ValueError, KeyError, TypeError):
        return False


def read_recovery_status():
    """Read the latest persisted recovery attempt for the dashboard."""
    try:
        data = json.loads(
            RECOVERY_STATUS_FILE.read_text(encoding="utf-8")
        )

        if not isinstance(data, dict):
            raise ValueError("Invalid recovery status format")

        attempts = data.get("attempts")
        if not isinstance(attempts, list):
            attempts = data.get("active_attempts", [])

        if not isinstance(attempts, list) or not attempts:
            if check_service():
                return {
                    "status": "HEALTHY",
                    "detail": "Service health is fresh and healthy. No recovery attempts recorded.",
                    "attempts": [],
                }
            return {
                "status": "UNKNOWN",
                "detail": "No recovery attempts are recorded and service health is unavailable or stale.",
                "attempts": [],
            }

        latest = attempts[-1]
        if not isinstance(latest, dict):
            raise ValueError("Invalid recovery attempt")

        state = str(latest.get("status", "pending")).lower()
        verified = bool(latest.get("verified", False))

        if state in ("success", "verified") and verified:
            status = "SUCCESS"
            detail = (
                f'{latest.get("classification", "Recovery")} completed: '
                f'{latest.get("action", "action")} was verified.'
            )
        elif state in ("failed", "error"):
            status = "FAILED"
            detail = str(
                latest.get("error") or "Recovery execution failed."
            )
        elif state in ("success", "verified"):
            status = "PENDING"
            detail = "Recovery action completed but verification is not confirmed."
        else:
            status = "PENDING"
            detail = f"Recovery attempt status: {state}."

        return {
            "status": status,
            "detail": detail,
            "attempts": attempts,
            "latest": latest,
        }

    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        if check_service():
            return {
                "status": "HEALTHY",
                "detail": "Service health is fresh and healthy. Recovery history is unavailable.",
                "attempts": [],
            }
        return {
            "status": "UNKNOWN",
            "detail": f"Recovery history unavailable: {exc}",
            "attempts": [],
        }


@app.route("/")
def index():
    return render_template_string(PAGE.replace("__ACN_POWER_NONCE__", POWER_NONCE))


@app.route("/api/status")
def api_status():
    faults = read_faults()
    recovery = read_recovery_status()
    detection = build_detection_payload()

    power = power_status(detection)
    health, code = proxy_mininet("/api/recovery/health", timeout=2)
    if code != 200:
        health = {"ok": False, "state": "UNKNOWN", "error": "Independent health API unavailable"}
    try:
        history = json.loads(RECOVERY_STATUS_FILE.read_text())
        if not isinstance(history, dict):
            history = {}
    except (OSError, ValueError, TypeError):
        history = {}
    monitor = build_monitor(detection, history, health, power)

    return jsonify({
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "service": {"healthy": check_service()},
        "faults": faults,
        "recovery": recovery,
        "detection": detection,
        "automatic_recovery": {"enabled": power["enabled"], "source": "shared_power_file"},
        "power": power,
        "system_health": monitor,
        "independent_checks": health,
        "classification": {
            "available": detection.get("classified_count", 0) > 0
            or detection.get("engine") in ("detect_service", "live_eval"),
            "labels": [
                item.get("classification")
                for item in detection.get("active") or []
            ],
        },
    })



def power_status(detection=None):
    state = power_control.status(POWER_FILE)
    detection = detection if detection is not None else read_detection_status() or {}
    state['detector_acknowledged'] = (detection.get('engine') == 'detect_service'
        and fresh(detection.get('checked_at'), 15)
        and detection.get('power_revision') == state['revision'])
    return state


@app.after_request
def disable_status_cache(response):
    if request.path in ('/', '/api/status', '/api/power'):
        response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/api/power', methods=['GET', 'POST'])
def main_power():
    if request.method == 'GET':
        return jsonify(ok=True, power=power_status(), policies=RECOVERY_POLICIES)
    # The existing dashboard is local-only. Protect the new privileged control
    # against cross-origin forms/fetches and stale browser-tab updates.
    origin = request.headers.get('Origin')
    if (urlsplit(request.host_url).hostname not in ('127.0.0.1', 'localhost', '::1')
            or (origin and origin.rstrip('/') != request.host_url.rstrip('/'))
            or request.headers.get('Sec-Fetch-Site') == 'cross-site'
            or not hmac.compare_digest(request.headers.get('X-Power-CSRF', ''), POWER_NONCE)):
        return jsonify(ok=False, error='Same-origin power authorization required; reload the dashboard'), 403
    payload = request.get_json(silent=True)
    if (not isinstance(payload, dict) or set(payload) != {'enabled', 'expected_revision'}
            or type(payload.get('enabled')) is not bool
            or type(payload.get('expected_revision')) is not int or payload['expected_revision'] < 0):
        return jsonify(ok=False, error='Explicit enabled boolean and expected_revision integer required'), 400
    if payload['enabled']:
        state = power_status()
        if not state['valid'] or not state['detector_acknowledged']:
            return jsonify(ok=False, error='Start/reload the updated detector and wait for its fresh power acknowledgement first'), 409
        api, code = proxy_mininet('/health', timeout=2)
        required = {'shared_power_v1', 'classified_recovery_v3', 'independent_health_v1'}
        if code != 200 or not required.issubset(set(api.get('recovery_capabilities', []))):
            return jsonify(ok=False, error='Updated guarded topology API is not active. Load installed code before enabling power.'), 503
    try:
        state = power_control.set_enabled(payload['enabled'], payload['expected_revision'], POWER_FILE)
        return jsonify(ok=True, power=power_status(), message=state['detail'])
    except power_control.PowerConflict as exc:
        return jsonify(ok=False, error=str(exc), power=power_status()), 409
    except OSError:
        return jsonify(ok=False, error='Could not safely persist power state; inspect file permissions'), 503


def read_service_config():
    try:
        return SERVICE_CONFIG.read_text(encoding="utf-8").strip()
    except OSError:
        return "mode=missing"


def write_service_config(value):
    SERVICE_CONFIG.write_text(value + "\n", encoding="utf-8")


def config_is_faulted():
    return read_service_config() != HEALTHY_CONFIG


def status_reports_unhealthy():
    try:
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        checked_at = datetime.fromisoformat(data["checked_at"])
        age = (datetime.now(checked_at.tzinfo) - checked_at).total_seconds()
        return age <= 10 and not bool(data["healthy"])
    except (OSError, ValueError, KeyError, TypeError):
        return False


def set_config_pipeline(**kwargs):
    _config_pipeline.update(kwargs)


def restore_service_config():
    write_service_config(HEALTHY_CONFIG)


def proxy_mininet(path, method="GET", payload=None, timeout=4):
    url = MININET_API + path
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    api_request = urllib.request.Request(
        url, data=body, headers=headers, method=method,
    )
    try:
        with urllib.request.urlopen(api_request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8")), 200
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(detail)
            message = parsed.get("error", detail)
        except json.JSONDecodeError:
            message = detail
        return {
            "ok": False,
            "error": f"Topology API rejected the operation: {message}",
        }, 502
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "ok": False,
            "error": (
                "Cannot reach the Mininet control API. "
                "Check that topo_large.py is still running. "
                f"Details: {exc}"
            ),
        }, 503


def watch_config_and_recover(job_id):
    """Legacy entry point: recovery execution belongs to the gated executor."""
    with _config_job_lock:
        if job_id != _config_job_id:
            return
    set_config_pipeline(
        detected=False,
        recovered=False,
        detail="Dashboard recovery watcher retired; use the gated recovery executor.",
    )


def start_config_recovery_watch():
    global _config_job_id
    with _config_job_lock:
        _config_job_id += 1
        job_id = _config_job_id
    threading.Thread(
        target=watch_config_and_recover,
        args=(job_id,),
        daemon=True,
    ).start()


def cancel_config_recovery_watch():
    global _config_job_id
    with _config_job_lock:
        _config_job_id += 1


def handle_config_fault(action):
    result, code = proxy_mininet(
        "/api/config",
        method="POST",
        payload={"action": action},
    )

    if code == 200 and result.get("ok"):
        if action == "enable":
            set_config_pipeline(
                detected=False,
                recovered=False,
                detail="Invalid configuration injected through Mininet control API. Detection and recovery remain under the existing safety gates.",
            )
        else:
            cancel_config_recovery_watch()
            set_config_pipeline(
                detected=_config_pipeline.get("detected", False),
                recovered=True,
                detail="Service configuration restored to mode=ok through Mininet control API.",
            )

    return result, code


@app.route("/api/fault", methods=["POST"])
def control_fault():
    payload = request.get_json(silent=True) or {}
    action = payload.get("action")
    fault_id = payload.get("id")

    if fault_id not in IMPLEMENTED_FAULTS or action not in ("enable", "disable"):
        return jsonify({
            "ok": False,
            "error": (
                "Unknown fault or action. Supported faults: link, config, switch, service, process, controller, path."
            ),
        }), 400

    if fault_id == "config":
        result, code = handle_config_fault(action)
        return jsonify(result), code

    api_paths = {
        "link": "/api/link",
        "switch": "/api/switch",
        "service": "/api/service",
        "process": "/api/process",
        "controller": "/api/controller",
        "path": "/api/path",
    }
    result, code = proxy_mininet(api_paths[fault_id], method="POST", payload={"action": action})
    return jsonify(result), code


@app.route("/api/link/status")
def dashboard_link_status():
    result, code = proxy_mininet("/api/link/status", timeout=3)
    return jsonify(result), code


@app.route("/api/config/status")
def dashboard_config_status():
    result, code = proxy_mininet("/api/config/status", timeout=3)

    if code != 200 or not result.get("ok"):
        return jsonify(result), code

    result.update({
        "healthy": check_service(),
        "detected": bool(_config_pipeline.get("detected")),
        "recovered": bool(_config_pipeline.get("recovered")),
        "detail": _config_pipeline.get("detail"),
    })
    return jsonify(result), 200


@app.route("/api/switch/status")
def dashboard_switch_status():
    result, code = proxy_mininet("/api/switch/status", timeout=3)
    return jsonify(result), code


@app.route("/api/observe")
def dashboard_observe():
    result, code = proxy_mininet("/api/observe", timeout=3)
    return jsonify(result), code


@app.route("/api/<fault_id>/status")
def dashboard_extra_fault_status(fault_id):
    api_paths = {
        "service": "/api/service/status",
        "process": "/api/process/status",
        "controller": "/api/controller/status",
        "path": "/api/path/status",
    }
    if fault_id not in api_paths:
        return jsonify({"ok": False, "error": "Unknown fault status"}), 404
    result, code = proxy_mininet(api_paths[fault_id], timeout=3)
    return jsonify(result), code



# RYU_DASHBOARD_CONTROL_V1 backend
def ryu_port_is_open():
    try:
        with socket.create_connection((RYU_HOST, RYU_PORT), timeout=0.5):
            return True
    except OSError:
        return False


def ryu_status_data():
    managed = _ryu_process is not None and _ryu_process.poll() is None
    listening = ryu_port_is_open()
    return {
        "ok": True,
        "running": managed or listening,
        "managed": managed,
        "pid": _ryu_process.pid if managed else None,
        "listening": listening,
        "port": RYU_PORT,
        "busy": False,
    }


@app.route("/api/ryu/status")
def ryu_status():
    return jsonify(ryu_status_data())



@app.route("/api/ryu/start", methods=["POST"])
def ryu_start():
    global _ryu_process

    with _ryu_lock:
        if _ryu_process is not None and _ryu_process.poll() is None:
            return jsonify({
                "ok": True,
                "message": "Ryu is already running.",
                **ryu_status_data(),
            })

        if ryu_port_is_open():
            return jsonify({
                "ok": False,
                "error": "Port 6633 is occupied by another controller.",
            }), 409

        if not RYU_BIN.is_file():
            return jsonify({
                "ok": False,
                "error": f"Ryu executable not found: {RYU_BIN}",
            }), 500

        try:
            RYU_LOG.parent.mkdir(parents=True, exist_ok=True)

            with RYU_LOG.open("a", buffering=1) as log_file:
                log_file.write("\\n--- Ryu start requested ---\\n")
                _ryu_process = subprocess.Popen(
                    [
                        str(RYU_BIN),
                        "--ofp-tcp-listen-port",
                        str(RYU_PORT),
                        "ryu.app.simple_switch_stp_13",
                    ],
                    cwd=str(BASE_DIR),
                    stdin=subprocess.DEVNULL,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )

            deadline = time.time() + 10

            while time.time() < deadline:
                if _ryu_process.poll() is not None:
                    raise RuntimeError(
                        "Ryu exited during startup. Check logs/ryu.log."
                    )

                if ryu_port_is_open():
                    return jsonify({
                        "ok": True,
                        "message": (
                            f"Ryu is running successfully. "
                            f"PID {_ryu_process.pid}, port {RYU_PORT}."
                        ),
                        **ryu_status_data(),
                    })

                time.sleep(0.25)

            raise RuntimeError(
                "Ryu did not open port 6633 within 10 seconds."
            )

        except Exception as exc:
            if _ryu_process is not None and _ryu_process.poll() is None:
                _ryu_process.terminate()
                try:
                    _ryu_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _ryu_process.kill()
                    _ryu_process.wait()

            _ryu_process = None

            return jsonify({
                "ok": False,
                "error": str(exc),
            }), 500


@app.route("/api/ryu/stop", methods=["POST"])
def ryu_stop():
    global _ryu_process

    with _ryu_lock:
        if _ryu_process is None or _ryu_process.poll() is not None:
            if ryu_port_is_open():
                return jsonify({
                    "ok": False,
                    "error": "A controller is listening on port 6633, but this dashboard did not start it. Stop it from its original terminal.",
                }), 409

            _ryu_process = None
            return jsonify({
                "ok": True,
                "message": "Ryu is already stopped.",
                **ryu_status_data(),
            })

        process = _ryu_process

        try:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

            _ryu_process = None

            return jsonify({
                "ok": True,
                "message": "Dashboard-managed Ryu process stopped.",
                **ryu_status_data(),
            })

        except Exception as exc:
            return jsonify({
                "ok": False,
                "error": f"Could not stop Ryu: {exc}",
            }), 500



# ACN_NETWORK_CONTROLS_V1
NETWORK_HELPER = "/usr/local/sbin/acn-network-control"

def run_network_helper(action, timeout=75):
    allowed = {"status", "start", "stop", "clean", "restart"}
    if action not in allowed:
        raise ValueError("Unsupported network operation")
    result = subprocess.run(
        ["sudo", "-n", NETWORK_HELPER, action],
        capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError(
            result.stderr.strip() or result.stdout.strip() or
            "Network helper failed"
        )
    return result.stdout.strip()

def topology_api_ready():
    try:
        with urllib.request.urlopen(
            MININET_API + "/health", timeout=1
        ) as response:
            return response.status == 200
    except Exception:
        return False

@app.route("/api/network/status")
def network_status():
    try:
        state = run_network_helper("status", timeout=5)
        return jsonify({
            "ok": True,
            "state": state,
            "api": topology_api_ready()
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503

@app.route("/api/network/clean", methods=["POST"])
def network_clean():
    try:
        message = run_network_helper("clean")
        return jsonify({"ok": True, "message": message})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 409

@app.route("/api/network/restart", methods=["POST"])
def network_restart():
    try:
        message = run_network_helper("restart", timeout=100)
        return jsonify({"ok": True, "message": message})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 409

@app.route("/api/network/full-restart", methods=["POST"])
def network_full_restart():
    global _ryu_process
    try:
        # Stop managed Ryu first so the new topology gets a clean controller.
        if _ryu_process is not None and _ryu_process.poll() is None:
            _ryu_process.terminate()
            try:
                _ryu_process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                _ryu_process.kill()
                _ryu_process.wait(timeout=3)

        _ryu_process = None

        message = run_network_helper("restart", timeout=100)

        # Wait for the topology API before starting the controller.
        deadline = time.time() + 15
        while time.time() < deadline and not topology_api_ready():
            time.sleep(1)

        if not topology_api_ready():
            raise RuntimeError(
                "Mininet started but topology API did not become ready. Check logs/mininet.log."
            )

        # Start Ryu using the existing dashboard-managed Ryu function.
        with _ryu_lock:
            if ryu_port_is_open():
                raise RuntimeError(
                    "Port 6633 is occupied by an unmanaged controller."
                )
            RYU_LOG.parent.mkdir(parents=True, exist_ok=True)
            with RYU_LOG.open("a", buffering=1) as log_file:
                _ryu_process = subprocess.Popen(
                    [
                        str(RYU_BIN),
                        "--ofp-tcp-listen-port", str(RYU_PORT),
                        "ryu.app.simple_switch_stp_13",
                    ],
                    cwd=str(BASE_DIR),
                    stdin=subprocess.DEVNULL,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )

        return jsonify({
            "ok": True,
            "message": message + " Ryu restart requested. Check logs/ryu.log."
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 409


if __name__ == "__main__":
    print("ACN dashboard starting at http://127.0.0.1:5000", flush=True)
    app.run(host="127.0.0.1", port=5000, debug=False)
