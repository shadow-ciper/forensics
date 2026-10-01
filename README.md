# forensics

Incident response and network forensics casework. Each case holds the evidence
as committed, the analysis, the detection rules that came out of it, and the
playbook the response followed.

## sample1 — DNS remote shell (covert channel over port 53)

A Windows XP host was accessed by an internal attacker across three covert
sessions on ports 53, 23 and 80. Running filesystem enumeration over TCP/53 is a
firewall-evasion technique: the traffic passes anything filtering by port,
because to that traffic port 53 *is* DNS.

| Path | What it is |
|---|---|
| `pcap/dns-remoteshell.pcap` | the evidence, 131 packets over 99.7s |
| `pcap/slammer.pcap` | comparison capture, 458 bytes |
| `analysis/FORENSIC-REPORT.md` | full report — executive summary, affected assets, timeline, IOCs, 16 Snort rules with validation |
| `rules/dns-remoteshell.rules` | the 16 detection rules |
| `snort/snort_custom.conf` | rule config used to validate them |
| `snort/snort_alerts_output.txt` | the alert output that validated them |
| `playbook/IR-Playbook-Network-Forensics.md` | the IR playbook, in Markdown, HTML and PDF |
| `evidence/evidence1-4.png` | supporting screenshots |

## Chain of custody

Evidence hashes are recorded in the report and verifiable against the committed
file:

```
SHA-256  8c89c0d2d5b91695a03d05a451897f583a99d2379afac0822af0d8f390163d95
MD5      3451fc588eb703545b4ecd26d203acb5
```

## Method

The 16 Snort rules were validated against the capture and reported at a 100%
detection rate, with the alert output committed alongside them. That is the part
that matters: a detection rule nobody validated against known-bad traffic is a
claim, not a control.

## Limitations

- **Synthetic lab evidence.** `dns-remoteshell.pcap` is a constructed sample, not
  a real capture. `slammer.pcap` is a 458-byte stub, enough to illustrate the
  format and not enough to analyse.
- **Windows XP host.** The target OS is long out of support. The technique is
  still current; the host profile is not.
- **No detection tooling.** The rules exist as text. Nothing here loads them into
  a live sensor, which is the gap
  [threat-hunter-toolkit](https://github.com/shadow-ciper/threat-hunter-toolkit)
  was built to close.
