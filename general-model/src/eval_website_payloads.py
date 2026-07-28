"""Score Evangeline's 16 website payloads through the shipped AURA gate.

These are 16 web-delivered prompt-injection payloads, every one labelled 1 (the attack
succeeded). There are no benign controls in the set, so ONLY recall is measurable here;
any precision or false-alarm number would be undefined. Stated rather than implied.

The gate has layers that apply differently to web content:
  RULE   - keyed on tool params (shell/secret/exfil); not applicable to a page body
  ECHO   - reply reproduces a distinctive token from the untrusted page: DIRECTLY applicable
  COMPLIANCE - labeler + evidence bar + deferred score over (prompt, reply)
We report ECHO and COMPLIANCE, using the page's poison_evidence as the ingested content.
"""
import sys, json, os
ROOT="/Users/sid/Documents/Behavioral Risk Prediction for Autonomous AI Systems"
REPO=("/private/tmp/claude-501/-Users-sid-Documents-Behavioral-Risk-Prediction-for-Autonomous"
      "-AI-Systems/69306e3f-efd6-48e7-a076-fc2873ce40b2/scratchpad/opals")
sys.path.insert(0,ROOT+"/analysis"); sys.path.insert(0,ROOT+"/openclaw-plugin")
import scorer

rows=json.load(open(REPO+"/evangeline_website_tests/16_payloads_70_vectors.json"))
print(f"  {len(rows)} payloads, labels: {set(r.get('label') for r in rows)}\n")
print(f"  {'#':>2} {'type':34s} {'echo':>5} {'compl':>6} {'ANY':>4}")
ne=nc=na=0
detail=[]
for i,r in enumerate(rows,1):
    rep = r.get("agent_response") or ""
    poison = r.get("poison_evidence") or ""
    if isinstance(poison,(list,tuple)): poison=" ".join(map(str,poison))
    e = scorer._echo(rep, str(poison)) > 0
    c = scorer._compliance_layers(str(poison)[:2000], rep, [])[0] > 0
    a = e or c
    ne+=e; nc+=c; na+=a
    print(f"  {i:2d} {str(r.get('type'))[:34]:34s} {('YES' if e else '-'):>5} "
          f"{('YES' if c else '-'):>6} {('CAUGHT' if a else 'miss'):>4}")
    if not a: detail.append((i,str(r.get('type')),rep[:150]))
n=len(rows)
print(f"\n  ECHO layer      : {ne}/{n} = {100*ne/n:.0f}%")
print(f"  COMPLIANCE layer: {nc}/{n} = {100*nc/n:.0f}%")
print(f"  EITHER (recall) : {na}/{n} = {100*na/n:.0f}%")
if detail:
    print("\n  MISSED:")
    for i,t,s in detail: print(f"    [{i}] {t}: {' '.join(s.split())[:110]}")
json.dump({"n":n,"echo":ne,"compliance":nc,"either":na,
           "note":"all 16 labelled 1; no benign controls, so precision is undefined"},
          open(ROOT+"/analysis/website_payload_results.json","w"), indent=2)
