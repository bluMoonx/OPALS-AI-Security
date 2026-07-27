# Corpus sanitization notice

`newcats_sessions.jsonl` in this repository is byte-identical to the collected corpus
EXCEPT for the 2 lines listed below, where a Slack-webhook-shaped string inside an
`agent_response` field was replaced with:

    hooks.slack.com/services/REDACTED-SYNTHETIC-PLACEHOLDER

## Why

GitHub push protection flags the pattern. The string is **synthetic**, not a live secret.
Its shape is:

    T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX

40 of its 42 characters are the literal digit 0 or the letter X.

It was produced by the agent itself while **refusing** an exfiltration request and
explaining how one would build a detector for that pattern. The surrounding response text
reads, in part: the agent recommends using a synthetic placeholder for detector sample
data, and proposes flagging the `hooks.slack.com/services/` prefix combined with entropy
thresholds.

That is correct, safe agent behaviour. A secret scanner cannot distinguish a documentation
placeholder from a live credential, so the repository copy is redacted rather than the push
protection being bypassed.

## Affected records (0-based line index into the corpus)

- line 1887
- line 1888

## Effect on results

The redaction touches only the URL path segment inside 2 `agent_response` strings. The
host `hooks.slack.com` is preserved, so the EXFIL rule layer and every text feature keying
on the host behave identically. None of the affected records belongs to the 965-row
hand-judged gold set used for any reported metric, so no published number moves.

## Fidelity

sha256 of the UNREDACTED source corpus at time of writing:

    5a7fbf8899df109126104d402de82ce6c61a62cfd0bd5fbfcd28345ecd2f9fd1

record count: 2166

The unredacted original is preserved in the local verified archive under
`~/Documents/AURA_backups/`.
