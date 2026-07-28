import sys, json
ROOT=(os.environ.get("AURA_ROOT") or os.path.dirname(os.path.abspath(__file__)))
REPO=("/private/tmp/claude-501/-Users-sid-Documents-Behavioral-Risk-Prediction-for-Autonomous"
      "-AI-Systems/69306e3f-efd6-48e7-a076-fc2873ce40b2/scratchpad/opals")
sys.path.insert(0,ROOT+"/analysis"); sys.path.insert(0,ROOT+"/openclaw-plugin")
from eval_combined_gold import load_records, load_all_gold
from deferred_compliance import parse_demand

gold=load_all_gold(load_records())
ours=[g["_rec"].get("prompt") for g in gold if g.get("condition")=="attack"]
new=[json.loads(l) for l in open(REPO+"/prompt-injection/dataset/sessions_tierlabeled.jsonl",errors="ignore") if l.strip()]
foreign=[r.get("user_prompt") for r in new if r.get("attack_category")!="benign"]

def truthy(v):
    if isinstance(v,(set,list,tuple,dict)): return len(v)>0
    if isinstance(v,bool): return v
    if isinstance(v,(int,float)): return v>0
    if isinstance(v,str): return bool(v.strip())
    return bool(v)

def rate(prompts,k):
    n=0
    for p in prompts:
        try: d=parse_demand(p or "")
        except Exception: continue
        if truthy(d.get(k)): n+=1
    return n/max(len(prompts),1)

try: keys=sorted(parse_demand(ours[0] or "").keys())
except Exception: keys=[]
print(f"  {'demand component':28s} {'ours':>7s} {'foreign':>8s}   gap")
rows=[(rate(ours,k), rate(foreign,k), k) for k in keys]
for o,f,k in sorted(rows, key=lambda t:-(t[0]-t[1])):
    flag = "  <-- THE GAP" if (o-f)>0.20 else ""
    print(f"    {k:28s} {o:7.3f} {f:8.3f}   {f-o:+.3f}{flag}")
