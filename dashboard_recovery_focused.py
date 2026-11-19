#!/usr/bin/env python3
"""ACN SDN Fault Detection & Recovery dashboard.

The seven fault-injection controls are currently UI simulations only. They do
not change Mininet, Open vSwitch, Linux processes, or the Ryu controller.
The existing service health and recorded fault history still come from the
project's real status/log files.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string

BASE_DIR = Path(__file__).resolve().parent
FAULT_LOG = BASE_DIR / "logs" / "faults.jsonl"
STATUS_FILE = BASE_DIR / "logs" / "service_status.json"

app = Flask(__name__)

PAGE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACN | SDN Fault Recovery Dashboard</title>
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
.pill{white-space:nowrap;border:1px solid #69552c;background:#342a17;color:var(--amber);padding:7px 10px;border-radius:99px;font-size:10px;font-weight:800;letter-spacing:.7px}
main{max-width:1450px;margin:22px auto;padding:0 18px 35px}
.layout{display:grid;grid-template-columns:minmax(300px,.78fr) minmax(0,1.55fr);gap:16px;align-items:start}
.panel{background:linear-gradient(180deg,rgba(23,34,56,.97),rgba(18,26,45,.98));border:1px solid var(--line);border-radius:16px;overflow:hidden;box-shadow:0 14px 38px #0002}
.panel-head{padding:16px 18px 0;display:flex;justify-content:space-between;align-items:center;gap:10px}
.panel-head h2{font-size:16px;margin:0}
.panel-body{padding:15px 18px 18px}
.muted{color:var(--muted)}
.small{font-size:11px;color:var(--muted)}
.kicker{font-size:10px;text-transform:uppercase;letter-spacing:1.2px;font-weight:800;color:var(--muted)}
button{border:0;cursor:pointer;border-radius:8px;padding:8px 10px;font-weight:800;font-size:11px;transition:filter .15s}
button:hover{filter:brightness(1.12)}
button:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
button:disabled{opacity:.38;cursor:not-allowed}
.enable{background:#1e694d;color:#eafff5}
.disable{background:#432633;border:1px solid #633341;color:#ffc2cb}
.secondary{background:#263650;border:1px solid #3a4d6a;color:#e0eaff}
.fault-list{display:grid;gap:9px}
.fault-item{border:1px solid var(--line);border-radius:11px;padding:11px 12px;background:#080e1c66}
.fault-item.active{border-color:#a63e53;background:#311c2a88}
.fault-item-top{display:flex;align-items:flex-start;gap:9px}
.icon{width:29px;height:29px;border-radius:8px;background:#1b2a44;display:grid;place-items:center;flex-shrink:0;font-size:15px}
.fault-name{font-weight:800;font-size:12px;line-height:1.3}
.fault-desc{font-size:10px;color:var(--muted);margin-top:3px}
.fault-controls{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:9px}
.state{font-size:9px;letter-spacing:.4px;font-weight:900;color:var(--green)}
.state.active{color:var(--red)}
.actions{display:flex;gap:6px}
.actions button{padding:7px 9px}
#clearAll{font-size:10px}
.monitor-hero{padding:20px;border:1px solid var(--line);border-radius:13px;background:#080e1c66;display:flex;gap:15px;align-items:center;margin-bottom:13px}
.big-dot{width:14px;height:14px;border-radius:50%;background:var(--green);box-shadow:0 0 0 6px #42d39218;flex-shrink:0}
.big-dot.bad{background:var(--red);box-shadow:0 0 0 6px #ff667a18}
.hero-title{font-size:clamp(18px,2vw,24px);font-weight:900;letter-spacing:-.5px}
.hero-detail{font-size:12px;color:var(--muted);margin-top:4px}
.badge{margin-left:auto;border-radius:99px;padding:7px 10px;background:#14372d;color:var(--green);font-size:10px;font-weight:900;white-space:nowrap}
.badge.bad{background:#421f2a;color:var(--red)}
.badge.wait{background:#342a17;color:var(--amber)}
.recovery-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:13px}
.metric{padding:13px;border:1px solid var(--line);border-radius:11px;background:#080e1c66;min-width:0}
.metric-label{font-size:11px;color:var(--muted)}
.metric-value{font-size:20px;font-weight:900;margin-top:5px;overflow-wrap:anywhere}
.metric-sub{font-size:10px;color:var(--muted);margin-top:3px}
.detected-box{border:1px solid var(--line);border-radius:12px;padding:14px;margin-top:12px}
.detected-box h3{font-size:13px;margin:0 0 10px}
.detected-list{display:grid;gap:8px}
.detected-row{display:flex;align-items:center;gap:9px;border-radius:9px;padding:10px;background:#311c2a66;border:1px solid #633341}
.detected-row .dot{width:7px;height:7px;background:var(--red);border-radius:50%;flex-shrink:0}
.detected-row strong{font-size:12px}
.detected-row small{display:block;color:var(--muted);font-size:10px;margin-top:2px}
.empty{font-size:12px;color:var(--muted);padding:7px 0}
.progress-steps{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:12px}
.step{border:1px solid var(--line);border-radius:9px;padding:11px 9px;background:#080e1c55}
.step-no{font-size:9px;color:var(--muted);font-weight:900;letter-spacing:.7px}
.step-name{font-size:11px;font-weight:800;margin-top:5px}
.step-state{font-size:9px;color:var(--amber);margin-top:5px;font-weight:800}
.step.done .step-state{color:var(--green)}
.step.active-step{border-color:#69552c}
.lower{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(270px,.8fr);gap:16px;margin-top:16px}
table{width:100%;border-collapse:collapse;min-width:500px}
th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line);font-size:11px;vertical-align:top}
th{color:var(--muted);font-size:9px;letter-spacing:.8px;text-transform:uppercase}
.table-wrap{overflow-x:auto}
.tag{display:inline-block;background:#421f2a;color:#ffc2cb;border-radius:99px;padding:4px 7px;font-size:9px;font-weight:900}
.healthy{color:var(--green)}.unhealthy{color:var(--red)}.neutral{color:var(--blue)}
.footnote{font-size:10px;color:var(--muted);margin-top:12px}
@media(max-width:980px){.layout{grid-template-columns:1fr}.fault-list{grid-template-columns:repeat(2,minmax(0,1fr))}.lower{grid-template-columns:1fr}}
@media(max-width:620px){header{align-items:flex-start;flex-direction:column}.fault-list{grid-template-columns:1fr}.recovery-grid{grid-template-columns:1fr}.progress-steps{grid-template-columns:repeat(2,minmax(0,1fr))}.panel-body{padding:13px}.panel-head{padding:14px 13px 0}}
</style>
</head>
<body>
<header>
  <div><h1>ACN | SDN Fault Detection &amp; Recovery</h1><p>Mininet topology · Open vSwitch · Ryu controller · Recovery monitoring</p></div>
  <span class="pill">PROTOTYPE · INJECTION BUTTONS SIMULATED</span>
</header>
<main>
  <div class="layout">
    <section class="panel">
      <div class="panel-head"><h2>Fault Injecting</h2><button class="secondary" id="clearAll">Disable All</button></div>
      <div class="panel-body">
        <p class="small" style="margin-top:0">Choose a scenario to simulate detection. Real injectors will be connected after the UI is approved.</p>
        <div class="fault-list" id="faultList"></div>
        <p class="footnote">These controls currently change demo state only; they do not modify live switches, links, or processes.</p>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head"><h2>Recovery Monitor</h2><span class="kicker">Primary monitor</span></div>
      <div class="panel-body">
        <div class="monitor-hero">
          <span id="heroDot" class="big-dot"></span>
          <div style="min-width:0"><div id="heroTitle" class="hero-title">System Ready</div><div id="heroDetail" class="hero-detail">No simulated faults are currently active.</div></div>
          <span id="heroBadge" class="badge">HEALTHY</span>
        </div>
        <div class="recovery-grid">
          <div class="metric"><div class="metric-label">Real service health · h2:8080</div><div class="metric-value neutral" id="realHealth">Checking…</div><div class="metric-sub">From existing service status file</div></div>
          <div class="metric"><div class="metric-label">Detected fault methods</div><div class="metric-value" id="activeCount">0 / 7</div><div class="metric-sub">Current demo injection state</div></div>
          <div class="metric"><div class="metric-label">Latest recovery status</div><div class="metric-value neutral" id="recoveryStatus">Checking…</div><div class="metric-sub" id="recoveryDetail">Loading actual service status</div></div>
        </div>

        <div class="detected-box">
          <h3>Detected Faults <span class="small" id="detectedSummary">(0 active)</span></h3>
          <div id="detectedList" class="detected-list"><div class="empty">No faults detected. Enable a scenario to see its name here.</div></div>
        </div>

        <div class="detected-box">
          <h3>Recovery Workflow</h3>
          <div class="progress-steps">
            <div class="step active-step" id="step1"><div class="step-no">STEP 01</div><div class="step-name">Fault Detection</div><div class="step-state" id="step1state">STANDBY</div></div>
            <div class="step" id="step2"><div class="step-no">STEP 02</div><div class="step-name">Classification</div><div class="step-state" id="step2state">WAITING</div></div>
            <div class="step" id="step3"><div class="step-no">STEP 03</div><div class="step-name">Recovery Engine</div><div class="step-state" id="step3state">NOT CONNECTED</div></div>
            <div class="step" id="step4"><div class="step-no">STEP 04</div><div class="step-name">Verification</div><div class="step-state" id="step4state">NOT CONNECTED</div></div>
          </div>
          <p class="footnote">The first two workflow states reflect the UI simulation. Recovery and verification will only be marked successful after integration with the real recovery engine and real checks.</p>
        </div>
      </div>
    </section>
  </div>

  <div class="lower">
    <section class="panel">
      <div class="panel-head"><h2>Real Fault History</h2><span class="kicker">logs/faults.jsonl</span></div>
      <div class="panel-body">
        <div class="table-wrap"><table><thead><tr><th>Detected at (UTC)</th><th>Type</th><th>Target</th><th>Details</th></tr></thead><tbody id="faults"><tr><td colspan="4">Loading fault history…</td></tr></tbody></table></div>
      </div>
    </section>
    <section class="panel">
      <div class="panel-head"><h2>System Summary</h2><span class="kicker">Live + demo</span></div>
      <div class="panel-body">
        <div class="metric" style="margin-bottom:9px"><div class="metric-label">Total recorded faults (real log)</div><div class="metric-value" id="totalRealFaults">—</div></div>
        <div class="metric"><div class="metric-label">Last real fault recorded</div><div class="metric-value" style="font-size:14px" id="latestRealFault">—</div></div>
        <p class="footnote">The event history above is read from the existing project log. Demo button events are intentionally kept separate from real fault records.</p>
      </div>
    </section>
  </div>
</main>
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
   <div class="fault-controls"><span class="state ${on?"active":""}">${on?"● DETECTED":"● NORMAL"}</span>
    <div class="actions"><button class="enable" data-action="enable" data-id="${s.id}" ${on?"disabled":""}>Enable</button><button class="disable" data-action="disable" data-id="${s.id}" ${!on?"disabled":""}>Disable</button></div>
   </div></article>`;
 }).join("");
}
function renderMonitor(){
 const count=active.size, bad=count>0;
 document.getElementById("activeCount").textContent=`${count} / 7`;
 document.getElementById("heroTitle").textContent=bad?"Fault Injection Detected":"System Ready";
 document.getElementById("heroDetail").textContent=bad?`${count} simulated fault ${count===1?"scenario is":"scenarios are"} active. Review the detected fault list below.`:"No simulated faults are currently active.";
 document.getElementById("heroDot").className="big-dot"+(bad?" bad":"");
 document.getElementById("heroBadge").textContent=bad?"FAULT DETECTED":"HEALTHY";
 document.getElementById("heroBadge").className="badge"+(bad?" bad":"");
 document.getElementById("detectedSummary").textContent=`(${count} active)`;
 const list=document.getElementById("detectedList");
 if(!bad){list.innerHTML='<div class="empty">No faults detected. Enable a scenario to see its name here.</div>';}
 else {list.innerHTML=scenarios.filter(s=>active.has(s.id)).map(s=>`<div class="detected-row"><span class="dot"></span><div><strong>${esc(s.name)}</strong><small>Demo fault active · Classification/recovery not yet connected</small></div><span class="badge bad">DETECTED</span></div>`).join("");}
 document.getElementById("step1state").textContent=bad?"DETECTED":"STANDBY";
 document.getElementById("step2state").textContent=bad?"AWAITING ENGINE":"WAITING";
 document.getElementById("step1").className="step"+(bad?" active-step":"");
 document.getElementById("step2").className="step"+(bad?" active-step":"");
}
faultList.addEventListener("click",e=>{
 const b=e.target.closest("button[data-action]");if(!b)return;
 const s=scenarios.find(x=>x.id===b.dataset.id);if(!s)return;
 if(b.dataset.action==="enable")active.add(s.id);else active.delete(s.id);
 renderFaultControls();renderMonitor();
});
document.getElementById("clearAll").addEventListener("click",()=>{active.clear();renderFaultControls();renderMonitor();});

async function refreshRealStatus(){
 try{
  const r=await fetch("/api/status",{cache:"no-store"});if(!r.ok)throw new Error("API "+r.status);
  const d=await r.json();
  const health=document.getElementById("realHealth");
  health.textContent=d.service.healthy?"HEALTHY":"UNHEALTHY";
  health.className="metric-value "+(d.service.healthy?"healthy":"unhealthy");
  document.getElementById("recoveryStatus").textContent=d.recovery.status;
  document.getElementById("recoveryStatus").className="metric-value "+(d.recovery.status==="HEALTHY"||d.recovery.status==="SUCCESS"?"healthy":"neutral");
  document.getElementById("recoveryDetail").textContent=d.recovery.detail;
  document.getElementById("totalRealFaults").textContent=d.faults.length;
  document.getElementById("latestRealFault").textContent=d.faults.length?(d.faults[d.faults.length-1].fault_type||"Unknown"):"No faults recorded";
  const body=document.getElementById("faults");body.replaceChildren();
  if(!d.faults.length){const row=body.insertRow();const c=row.insertCell();c.colSpan=4;c.textContent="No real faults recorded.";}
  else [...d.faults].reverse().forEach(f=>{
   const row=body.insertRow();
   [f.detected_at||"Unknown",f.fault_type||"Unknown",f.target||"Unknown",f.detail||""].forEach((v,i)=>{
    const c=row.insertCell();c.textContent=v;
    if(i===1){const tag=document.createElement("span");tag.className="tag";tag.textContent=v;c.replaceChildren(tag);}
   });
  });
 }catch(err){
  const h=document.getElementById("realHealth");h.textContent="CONNECTION ERROR";h.className="metric-value unhealthy";
  document.getElementById("recoveryStatus").textContent="UNKNOWN";
  document.getElementById("recoveryDetail").textContent="Could not read real status: "+err.message;
 }
}
renderFaultControls();renderMonitor();refreshRealStatus();setInterval(refreshRealStatus,5000);
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
                        records.append(record)
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return records


def check_service():
    try:
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        checked_at = datetime.fromisoformat(data["checked_at"])
        age = (datetime.now(checked_at.tzinfo) - checked_at).total_seconds()
        return bool(data["healthy"]) and age <= 10
    except (OSError, ValueError, KeyError, TypeError):
        return False


def read_recovery_status():
    healthy = check_service()
    if healthy:
        return {
            "status": "HEALTHY",
            "detail": "The service health endpoint is currently reported healthy by the detector.",
        }
    return {
        "status": "UNKNOWN",
        "detail": "The service is unhealthy or its latest status is stale. Check Mininet and h2.",
    }


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/api/status")
def api_status():
    faults = read_faults()
    recovery = read_recovery_status()
    return jsonify({
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "service": {"healthy": check_service()},
        "faults": faults,
        "recovery": recovery,
    })


if __name__ == "__main__":
    print("ACN dashboard starting at http://127.0.0.1:5000", flush=True)
    app.run(host="127.0.0.1", port=5000, debug=False)
