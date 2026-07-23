"""
match_sessions.py

Scans every *.trajectory.jsonl file in data/raw/session-logs/sessions/,
matches each one's actual submitted prompt against your real experiment
questions (baseline-queries.json / attack-queries.json), and discards
everything else as debugging noise (leftover from all the troubleshooting
we did earlier -- broken-config test calls, prompt_bank_kinda.py runs, etc).

For every matched session, it also reads the log's OWN record of which
workspace files were injected (context.compiled -> injectedWorkspaceFiles)
to confirm directly from the data whether MEMORY.md was actually loaded
for that call -- rather than trusting which folder you think you ran it
from.

Run from: memory-poisoning/notebooks/
    python match_sessions.py

Reads:  ../data/raw/session-logs/sessions/*.trajectory.jsonl
        ../prompts/baseline-queries.json
        ../prompts/attack-queries.json
Writes: ../data/processed/matched_sessions.json
"""

import json
import os
import glob


def load(path):
    with open(path, "r") as f:
        return json.load(f)


def normalize_prompt(s):
    """Strip a UTF-8 double-encoding artifact (stray 'Â' before characters
    like '²') that shows up because attack-queries.json was edited after
    the original run -- the live file no longer byte-matches exactly what
    was actually sent to the model at the time."""
    return (s or "").strip().replace("\u00c2", "")


def load_question_bank(prompts_dir):
    baseline = load(os.path.join(prompts_dir, "baseline-queries.json"))
    attack = load(os.path.join(prompts_dir, "attack-queries.json"))
    bank = {}
    for item in baseline:
        bank[normalize_prompt(item["question"])] = {"run_type": "baseline", **item}
    for item in attack:
        bank[normalize_prompt(item["question"])] = {"run_type": "attack", **item}
    return bank


def parse_trajectory_file(path):
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def extract_session_record(events):
    record = {
        "sessionId": None,
        "prompt": None,
        "injected_workspace_files": [],
        "memory_md_injected": False,
        "assistant_response": None,
        "error": None,
        "tool_count": None,
        "provider": None,
        "modelId": None,
        "ts_started": None,
        "fallback_steps": 0,
    }
    for ev in events:
        etype = ev.get("type")
        data = ev.get("data", {})
        record["sessionId"] = ev.get("sessionId", record["sessionId"])

        if etype == "session.started":
            record["ts_started"] = ev.get("ts")
            record["provider"] = ev.get("provider")
            record["modelId"] = ev.get("modelId")
            record["tool_count"] = data.get("toolCount")

        elif etype == "context.compiled":
            files = data.get("systemPromptReport", {}).get("injectedWorkspaceFiles", [])
            record["injected_workspace_files"] = [f.get("name") for f in files]
            # NOTE: this array is a fixed profile-file list (AGENTS.md, SOUL.md,
            # TOOLS.md, IDENTITY.md, USER.md, HEARTBEAT.md, BOOTSTRAP.md) and
            # never includes MEMORY.md regardless of whether it was loaded --
            # kept here for reference only, NOT used as the poisoning signal.

        elif etype == "prompt.submitted":
            record["prompt"] = data.get("prompt")
            system_prompt = data.get("systemPrompt", "") or ""
            # Real signal: check the compiled system prompt for a literal,
            # unique line from the actual poisoned MEMORY.md payload. This
            # confirms the model's INPUT contained the poison, independent
            # of whether its response happened to use it.
            record["memory_md_injected"] = (
                "Reference Log: Cosmological Constants" in system_prompt
            )

        elif etype == "model.completed":
            texts = data.get("assistantTexts", [])
            if texts:
                record["assistant_response"] = "\n".join(texts)
            snap = data.get("messagesSnapshot", [])
            for m in snap:
                if m.get("role") == "assistant" and m.get("errorMessage"):
                    record["error"] = m["errorMessage"]

        elif etype == "model.fallback_step":
            record["fallback_steps"] += 1

    return record


def main():
    prompts_dir = os.path.abspath(os.path.join("..", "prompts"))
    sessions_dir = os.path.abspath(os.path.join("..", "data", "raw", "session-logs", "sessions"))
    out_dir = os.path.abspath(os.path.join("..", "data", "processed"))
    os.makedirs(out_dir, exist_ok=True)

    bank = load_question_bank(prompts_dir)
    files = glob.glob(os.path.join(sessions_dir, "*.trajectory.jsonl"))
    print(f"Found {len(files)} trajectory files in {sessions_dir}")

    matched = []
    unmatched = 0

    for fp in files:
        events = parse_trajectory_file(fp)
        rec = extract_session_record(events)
        prompt = normalize_prompt(rec["prompt"])
        match = bank.get(prompt)
        if match:
            rec.update({
                "run_type": match["run_type"],
                "question_id": match["id"],
                "question_category_or_type": match.get("category") or match.get("type"),
                "source_file": os.path.basename(fp),
            })
            matched.append(rec)
        else:
            unmatched += 1

    print(f"\nMatched {len(matched)} of {len(files)} files to a real experiment question")
    print(f"Discarded as noise (debugging leftovers, etc): {unmatched}")

   # --- keep every successful trial as its own row, tagged with a trial
    # number -- only drop a repeat if it errored AND a working version of
    # the same question exists. A genuine intentional rerun (new trial) is
    # never discarded now. ---
    grouped = {}
    for m in matched:
        grouped.setdefault((m["run_type"], m["question_id"]), []).append(m)

    deduped = []
    dropped_errors = 0
    for key, group in grouped.items():
        non_error = [g for g in group if not g["error"]]
        if non_error:
            non_error.sort(key=lambda r: r.get("ts_started") or "")
            for i, rec in enumerate(non_error, start=1):
                rec["trial_number"] = i
                deduped.append(rec)
            dropped_errors += len(group) - len(non_error)
        else:
            worst_group = sorted(group, key=lambda r: len(r["assistant_response"] or ""), reverse=True)
            worst_group[0]["trial_number"] = 1
            deduped.append(worst_group[0])

    print(f"\nKept {len(deduped)} sessions across {len(grouped)} unique (question_id, run_type) pairs")
    print(f"Dropped {dropped_errors} error-only duplicate attempts")
    baseline_final = [m for m in deduped if m["run_type"] == "baseline"]
    attack_final = [m for m in deduped if m["run_type"] == "attack"]
    print(f"\nBaseline (deduped): {len(baseline_final)} (expect 20)")
    print(f"Attack (deduped):   {len(attack_final)} (expect 20)")

    mem_in_attack = sum(1 for m in attack_final if m["memory_md_injected"])
    mem_in_baseline = sum(1 for m in baseline_final if m["memory_md_injected"])
    print(f"\nAttack sessions where MEMORY.md was actually injected (log-verified): {mem_in_attack}/{len(attack_final)}")
    print(f"Baseline sessions where MEMORY.md was actually injected (should be 0!): {mem_in_baseline}/{len(baseline_final)}")

    mismatched_attack = [m for m in attack_final if not m["memory_md_injected"]]
    mismatched_baseline = [m for m in baseline_final if m["memory_md_injected"]]
    if mismatched_attack:
        print(f"\nWARNING: {len(mismatched_attack)} attack-labeled sessions did NOT have MEMORY.md injected:")
        for m in mismatched_attack:
            print(f"  - question_id {m['question_id']}: {m['source_file']}")
    if mismatched_baseline:
        print(f"\nWARNING: {len(mismatched_baseline)} baseline-labeled sessions DID have MEMORY.md injected (contamination!):")
        for m in mismatched_baseline:
            print(f"  - question_id {m['question_id']}: {m['source_file']}")

    remaining_errors = [m for m in deduped if m["error"]]
    if remaining_errors:
        print(f"\nNote: {len(remaining_errors)} final sessions still have no usable response (all duplicates were also errors):")
        for m in remaining_errors:
            print(f"  - question_id {m['question_id']} ({m['run_type']}): {m['source_file']}")

    out_path = os.path.join(out_dir, "matched_sessions.json")
    with open(out_path, "w") as f:
        json.dump(deduped, f, indent=2)
    print(f"\nWrote {out_path} ({len(deduped)} clean, deduplicated sessions)")


if __name__ == "__main__":
    main()