# Home SOC Lab — Segmented Network, Suricata IDS, and Wazuh SIEM

A self-built Security Operations Center lab that simulates a small company network with a firewall, a monitored target zone, and an isolated attacker zone. An external attacker is deliberately restricted to a single exposed web service by network segmentation, exploits an application-layer SQL injection vulnerability, and is detected by both network IDS (Suricata) and host-based monitoring (Wazuh agent + Sysmon) — demonstrating a complete, multi-layer SOC Analyst (Tier 1) workflow: monitoring, detection, and investigation.

## Objective

Most beginner home labs stop at "I installed a SIEM and generated some test alerts." This lab goes further: it builds realistic network segmentation (an attacker that can only reach one exposed port), carries out a genuine exploit against that single exposed service, and proves detection across two independent layers — the network perimeter and the compromised host — correlated in one SIEM dashboard.

## Architecture

| Zone | Purpose | Subnet | VMs |
|---|---|---|---|
| WAN | Internet access for the lab | 10.0.2.0/24 (NAT, DHCP) | pfSense only |
| LAN ("Target/Server" zone) | Protected zone — machines being defended and monitored | 192.168.10.0/24 | Ubuntu Server (Wazuh Manager/Indexer/Dashboard), Windows 10 (target) |
| OPT1 ("Attacker/DMZ" zone) | Isolated zone — holds the attacker machine | 192.168.20.0/24 | Kali Linux (attacker) |

```
Internet
    |
[ pfSense Firewall/Router ]
    |-------------------------------|
    v                               v
[ LAN — 192.168.10.0/24 ]      [ OPT1 (DMZ) — 192.168.20.0/24 ]
  • Ubuntu Server (Wazuh)          • Kali Linux (Attacker)
    192.168.10.10                   192.168.20.30
  • Windows 10 (Target)
    192.168.10.20
```

pfSense sits between every path. Kali (OPT1) can only reach the LAN zone because specific firewall rules on pfSense allow it — without those rules, pfSense blocks the traffic by default.

**Data flow:** Suricata (running on pfSense) inspects traffic crossing the LAN interface and writes alerts to a local `eve.json` file → a scheduled pull copies that file to the Wazuh manager → Wazuh's `logcollector` reads it → `analysisd` matches it against detection rules → alerts land in the dashboard. Windows 10 runs a Wazuh agent with Sysmon for endpoint-level visibility (process creation, registry changes, service creation), feeding the same dashboard independently.

## Threat Model

- **Attacker position:** external, placed in the untrusted OPT1 zone with no direct knowledge of the target beyond its IP.
- **Deliberate exposure:** pfSense's OPT1→LAN firewall rules were tightened to pass only TCP/80 to the target, with everything else explicitly blocked and logged. This mirrors a realistic "least privilege" perimeter rather than a flat, fully-open test network.
- **Technique:** SQL injection against a vulnerable web application (DVWA) running on the one exposed port, using `sqlmap`.

## Attack Timeline

### 1. Recon — only the intended port is reachable

```
$ nmap -Pn 192.168.10.20
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
```

Every port except 80 returns no response at all — silently dropped by the firewall rule, not by the host. Only the one deliberately-exposed service is visible from the attacker zone.

<img width="968" height="366" alt="01-nmap-recon" src="https://github.com/user-attachments/assets/65eca2a6-3c58-4256-bc57-9950026bdd0e" />


### 2. Exploitation — SQL injection confirmed with sqlmap

`sqlmap` against DVWA's SQLi lab (`/DVWA/vulnerabilities/sqli/?id=1`) confirmed the injection with **four separate techniques**:

- Boolean-based blind (`OR NOT 6252=6252#`)
- Error-based (`MySQL >= 5.0 ... FLOOR()`)
- Time-based blind (`SLEEP(5)`)
- UNION query (2-column UNION extraction)

Fingerprinted stack: **MySQL/MariaDB** backend, **Apache 2.4.58**, **PHP 8.0.30**, Windows host — all matching the real target.

<img width="986" height="1008" alt="02-sqlmap-exploit" src="https://github.com/user-attachments/assets/6cba6272-c3fc-437a-8e83-6293cdd7fb91" />


## Detection (Defender's View)

### 3. Perimeter — blocked recon attempts logged on pfSense

The firewall log shows the Block rule catching every connection attempt outside the one allowed path (here, scan traffic from the attacker zone `192.168.20.30` hitting dozens of ports on the target):

<img width="953" height="869" alt="03-pfsense-firewall-log" src="https://github.com/user-attachments/assets/ce7c6fcc-f0ee-4231-83d6-1d4effab96c9" />


### 4. Network IDS — Suricata alerts in the Wazuh dashboard

Suricata (rule group `suricata`, Wazuh rule ID **86601**) raised multiple alerts tied to the attack traffic, including `ET SCAN Potential SSH Scan OUTBOUND`, `SURICATA HTTP Response excessive header repetition`, and `ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response` — all correlated with real timestamps in the dashboard:

<img width="1917" height="951" alt="04-wazuh-suricata-alerts" src="https://github.com/user-attachments/assets/ab9eefca-05cc-4e7b-b452-2fed87c5e636" />


### 5. Host layer — MITRE ATT&CK-mapped endpoint activity

The Wazuh agent + Sysmon on the Windows target independently reported host-level activity mapped to MITRE ATT&CK techniques, including **T1570 (Lateral Movement)** and **T1543.003 (Persistence, Privilege Escalation — New Windows Service)**:

<img width="1906" height="937" alt="05-wazuh-mitre-attack-mapping" src="https://github.com/user-attachments/assets/1877834a-5e38-465d-9d44-ac256eec629d" />


### 6. Vulnerability management — endpoint CVE inventory

Wazuh's vulnerability detection module scanned the Windows 10 target's installed software and surfaced thousands of matched CVEs (high-severity examples: heap-based buffer overflows in Windows ALPC and the Biometric Service), demonstrating a second, independent detection capability beyond live attack monitoring:

<img width="1919" height="915" alt="06-wazuh-vulnerability-detection" src="https://github.com/user-attachments/assets/085b87df-4bc0-4ba8-9b2d-c2a702ec78bd" />


## Operational Challenges Encountered

Building this pipeline surfaced several real, non-obvious failures worth documenting — this is the kind of diagnostic work a SOC analyst actually does day to day:

- **Silent cron failure from a bad log redirect.** The scheduled Suricata log pull redirected output to `/var/log/`, a path a non-root user cannot write to. The shell failed on the redirect *before* the pull script ever ran, and cron swallowed the error — the log file simply never got created, with no visible failure anywhere, for days.
- **Wrong virtual NIC bound to the attacker's IP.** The attacker VM's static IP was configured on a different VirtualBox adapter than the one actually wired to the DMZ network, causing ARP resolution to silently fail (`Destination Host Unreachable`) despite every higher-layer setting looking correct.
- **Firewall rule direction mismatch.** An initial SQLi detection test failed because the relevant Suricata signatures are directional (`$EXTERNAL_NET → $HTTP_SERVERS`); traffic originating from inside the lab's own address space never matched, which required re-reading the actual rule definitions rather than assuming the signature was simply absent.
- **Self-inflicted SSH lockout via sshguard.** pfSense's brute-force protection auto-banned the Wazuh manager's own IP after a string of failed SSH attempts during pipeline debugging — the service was healthy the entire time, but packets were being silently dropped, producing a symptom indistinguishable from a real network or service outage until the ban list was checked directly.
- **SSH key authentication silently falling back to password.** An `authorized_keys` file with group/world-readable permissions on pfSense caused OpenSSH to reject key-based auth without any error message, falling back to interactive password prompts — which breaks unattended cron jobs with no visible failure.

Each of these was diagnosed by isolating the chain (ping → TCP connectivity → service status → config/permissions) rather than guessing, and confirmed fixed with a before/after test at each layer.

## MITRE ATT&CK Mapping

| Technique | Tactic | Where observed |
|---|---|---|
| T1595 — Active Scanning | Reconnaissance | nmap recon against the target |
| T1190 — Exploit Public-Facing Application | Initial Access | sqlmap SQL injection against DVWA |
| T1570 — Lateral Movement | Lateral Movement | Wazuh/Sysmon endpoint telemetry |
| T1543.003 — Create or Modify System Process: Windows Service | Persistence, Privilege Escalation | Wazuh/Sysmon endpoint telemetry |

## Stack

- **pfSense** — firewall/router, network segmentation, Suricata IDS
- **Suricata** — network intrusion detection, signature-based alerting
- **Wazuh** (Manager + Indexer + Dashboard) — SIEM, log correlation, vulnerability detection
- **Sysmon** — Windows endpoint telemetry (process, registry, network, file events)
- **Kali Linux** — attacker platform (`nmap`, `sqlmap`)
- **DVWA** — intentionally vulnerable web application target
