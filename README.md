# Lab: Configure TCP Wrappers for FTP (`vsftpd`)

**Series:** linux-ops-mastery — RHCSA TCP Wrappers & PAM
**Subjects covered:** `vsftpd` install/enable, `/etc/hosts.allow` / `/etc/hosts.deny` for FTP, **per-IP deny** patterns, `systemctl` + `ss -lntp`, RHEL 8+ libwrap reality check, pairing with `firewalld` for modern deployments
**Career arcs covered:** RHCSA (service + ACL wiring), RHCE (role variables for FTP hardening), SRE (temporary IP blocks), DevOps (legacy app FTP sunsets), AI (policy translation)
**Prerequisite:** Labs 68–70 (linkage + hosts.* mechanics)
**Time Estimate:** 30 to 45 minutes
**Difficulty arc:** Task 1 install · 2–3 enable/listen · 4 wrapper rules · 5 verify path · 6 capstone + full cleanup

---

## Objective

Install **`vsftpd`**, start the **FTP** listener, and practice **TCP Wrappers** rules that **deny a specific client IP** while permitting others — the classic **`vsftpd: DENY_IP`** pattern in `/etc/hosts.deny`, optionally balanced by **`vsftpd: ALLOW_SUBNET`** in `/etc/hosts.allow`.

You will verify whether **`vsftpd` is actually linked to `libwrap`** on your image. If not, you will still complete the **policy authoring** portion and document the **modern replacement** (`firewalld` rich rule rejecting source IP on port 21, or nftables equivalent).

> **Lab safety note:** FTP sends credentials in cleartext unless wrapped in TLS — this lab focuses on **access control mechanics**, not production FTP encouragement. Prefer **SFTP/SSH** in real life. Use a disposable VM.

---

## Concept: Service-Specific Lines in hosts.* (When libwrap Applies)

Each line names a **daemon list** (`vsftpd`) and a **client list** (IP/CIDR). TCP Wrappers applies the **first relevant match** from `hosts.allow`, then considers `hosts.deny`.

```
FTP client ──► tcp/21 ──► vsftpd
                 │
                 └─► libwrap? ──► consult hosts.allow / hosts.deny
```

> **Why this matters:** Global `ALL: ALL` deny breaks many services at once; **per-daemon** lines let you block **one misbehaving scanner IP** for FTP only.

---

## 📜 Why FTP + TCP Wrappers Showed Up on Exams — The Story

Academic labs loved **vsftpd** because it is quick to install, listens on a clear port, and historically sat beside **`hosts.deny` examples** in textbooks. Enterprise reality was messier: active/passive FTP traverses firewalls poorly, NAT breaks data channels, and credentials flew readable unless **FTPS** was configured.

Still, the **pedagogical point** endures: **network services need layered access control** — daemon config, kernel firewall, authentication, and (when present) **session-level host rules** like TCP Wrappers.

Red Hat removing TCP Wrappers from the platform pushed that layer to **`firewalld`**, **`nftables`**, and richer **`vsftpd` conf**. The exam skill of "write the deny line" remains valid on older curricula; the production skill is "verify enforcement."

> **The point of the story:** You are learning **pattern**, not blessing FTP. Pattern: **identify service → identify client predicate → write deny/allow → verify with traffic test**.

---

## 👪 The vsftpd + Wrappers Family — Who Lives There

### Service units and files

| Path | Role |
|---|---|
| `/usr/lib/systemd/system/vsftpd.service` | Unit file |
| `/etc/vsftpd/vsftpd.conf` | Primary daemon config |
| `/var/ftp` | Anonymous FTP root (default) |

### Wrapper patterns

| Line | Effect when libwrap active |
|---|---|
| `vsftpd: 203.0.113.77` in hosts.deny | Block that IP |
| `vsftpd: 198.51.100.0/255.255.255.0` in hosts.allow | Permit subnet |

> **The point of the family tree:** **FTP has two channels** (control + data). Wrapper checks typically happen on **control connection** creation; passive mode ports still need firewall forethought.

---

## 🔬 The Anatomy of `vsftpd: 203.0.113.77` — In One Diagram

```
hosts.deny:
  vsftpd : 203.0.113.77
     │       │      │
     │       │      └─ single offending client (TEST-NET-3 RFC5737)
     │       └──────── separator
     └──────────────── daemon keyword vsftpd matches libwrap process name
```

> **Reading rule:** Daemon keyword must match what `libwrap` sees — usually the **basename** of the server process.

---

## 📚 vsftpd / TCP Wrappers Reference Table

| Task | Command / file | Notes |
|---|---|---|
| Install | `dnf install -y vsftpd` | Non-interactive |
| Enable | `systemctl enable --now vsftpd` | Correct unit name |
| Listen check | `ss -lntp | grep ':21'` | Shows PID/program |
| Linkage proof | `ldd /usr/sbin/vsftpd | grep libwrap` | May be empty |
| Modern deny | `firewall-cmd --add-rich-rule='rule family="ipv4" source address="203.0.113.77" service name="ftp" reject'` | If wrappers absent |

> **Rule one of FTP labs:** After lab, **stop the service** unless your course needs it.

---

## 🎯 Career Pathway Sidebar

| Level | Why this lab matters |
|---|---|
| **RHCSA candidate** | Combines **unit enablement** + **hosts.* editing** |
| **RHCE candidate** | Ansible `firewalld` + `template` for vsftpd.conf |
| **SRE / Platform** | Temporary IP shuns belong in firewall, not folklore |
| **DevOps** | Deprecate cleartext FTP paths in pipelines |

---

## 🔧 The 6 Tasks

---

### Task 1 — Install vsftpd and record package version

**Purpose:** Baseline RPM state.

```bash
sudo -i
dnf install -y vsftpd
rpm -qi vsftpd | sed -n '1,12p'
```

**Human-Readable Breakdown:** Install server package and show metadata header.

**Reading it left to right:** root → dnf → rpm query slice.

**The story:** Package proof is part of defensible change logs.

**Expected output:**

```text
Installed:
  vsftpd-3.0.5-.el9.x86_64
Complete!
Name        : vsftpd
Version     : 3.0.5
...
```

**Switches**

| Token | Meaning |
|---|---|
| `-y` | Assume yes |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| No subscription | Attach repo or use CentOS Stream lab image |

---

### Task 2 — Enable service and confirm port 21 listener

**Purpose:** RHCSA muscle memory: **enable --now** + socket proof.

```bash
systemctl enable --now vsftpd
systemctl status vsftpd --no-pager -l | head -n 15

ss -lntp | grep ':21' || ss -lntp | grep vsftpd
```

**Human-Readable Breakdown:** Start on boot + now; `ss` proves LISTEN.

**Reading it left to right:** systemd → socket table filter.

**The story:** Examiners accept **evidence**, not assumptions.

**Expected output:**

```text
Active: active (running)
LISTEN 0 32 0.0.0.0:21 0.0.0.0:* users:(("vsftpd",pid=...,fd=3))
```

**Switches**

| Token | Meaning |
|---|---|
| `--now` | Start immediately |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `Address already in use` | Another FTP server — `ss -lntp` to identify |

---

### Task 3 — Prove libwrap linkage for vsftpd

**Purpose:** Same honesty checkpoint as sshd.

```bash
ldd /usr/sbin/vsftpd | grep libwrap || echo "vsftpd: no libwrap — hosts.* will NOT enforce for vsftpd on this build"
```

**Human-Readable Breakdown:** Determines whether upcoming edits are live or academic.

**Reading it left to right:** `ldd` pipeline.

**The story:** If empty, Task 4's **firewalld** snippet becomes the real enforcement peer.

**Expected output:**

```text
vsftpd: no libwrap — hosts.* will NOT enforce for vsftpd on this build
```

**Switches**

| Token | Meaning |
|---|---|
| `\|` | Pipe |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Positive libwrap | Proceed with hosts.* functional testing |

---

### Task 4 — Author hosts.allow / hosts.deny for deny-one-IP lab

**Purpose:** Deny **203.0.113.77** (TEST-NET-3 documentation IP — harmless placeholder) while allowing a lab subnet in allow file.

```bash
TS=$(date +%F-%H%M%S)
cp -a /etc/hosts.allow /root/hosts.allow.$TS
cp -a /etc/hosts.deny  /root/hosts.deny.$TS

cat > /etc/hosts.allow <<'EOF'
# Allow lab subnet for vsftpd — EDIT to your real network
vsftpd: 127.0.0.1
vsftpd: 198.51.100.0/255.255.255.0
EOF

cat > /etc/hosts.deny <<'EOF'
# Deny specific abusive client for vsftpd only
vsftpd: 203.0.113.77
ALL: ALL
EOF

chmod 644 /etc/hosts.allow /etc/hosts.deny
cat /etc/hosts.allow
echo '---'
cat /etc/hosts.deny
```

**Human-Readable Breakdown:** Allow broad lab access lines, deny specific IP, default deny all else.

**Reading it left to right:** backups → write allow → write deny → show.

**The story:** This is the **three-layer** story: specific deny, subnet allow, global deny.

**Expected output:**

```text
vsftpd: 127.0.0.1
vsftpd: 198.51.100.0/255.255.255.0
---
vsftpd: 203.0.113.77
ALL: ALL
```

**Switches**

| Token | Meaning |
|---|---|
| `vsftpd:` | Daemon keyword |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| Real client IP needed | Replace 198.51.100.0/24 with your desktop network |

---

### Task 5 — Optional functional test + modern firewall mirror

**Purpose:** If wrappers absent, install a **rich rule** that mirrors intent.

```bash
# If firewalld is running, add a reject rule (example — adjust zone)
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="203.0.113.77" port port="21" protocol="tcp" reject'
  firewall-cmd --reload
  firewall-cmd --list-rich-rules | grep 203.0.113.77 || true
else
  echo "firewalld inactive — skipping rich rule demo"
fi
```

**Human-Readable Breakdown:** Translate hosts.deny intent to **kernel-enforced** reject.

**Reading it left to right:** guard on firewalld → permanent add → reload → list.

**The story:** **This is the RHEL 9 truth path** when `libwrap` is missing.

**Expected output:**

```text
success
rule family="ipv4" source address="203.0.113.77" port port="21" protocol="tcp" reject
```

**Switches**

| Token | Meaning |
|---|---|
| `--permanent` | Survive reload/reboot after `--reload` |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `FirewallD is not running` | Expected on some sandboxes — note only |

---

### Task 6 — Capstone + cleanup (restore hosts.*, remove rules, stop FTP)

**Purpose:** Return system to safe defaults: **empty hosts files**, **remove rich rule**, **disable vsftpd**.

```bash
# Remove demo rich rule if added
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="203.0.113.77" port port="21" protocol="tcp" reject' 2>/dev/null || true
  firewall-cmd --reload
fi

truncate -s 0 /etc/hosts.allow
truncate -s 0 /etc/hosts.deny
chmod 644 /etc/hosts.allow /etc/hosts.deny

systemctl disable --now vsftpd
dnf remove -y vsftpd
```

**Cleanup**

```bash
rm -f /root/hosts.allow.* /root/hosts.deny.* 2>/dev/null
exit
```

**Human-Readable Breakdown:** Undo firewall lab artifact, blank hosts.*, stop + remove FTP.

**Reading it left to right:** rich rule removal → truncate → systemd disable → dnf remove.

**The story:** **Capstone = prove you can leave the machine cleaner than you found it.**

**Expected output:**

```text
success
Removed vsftpd ...
```

**Switches**

| Token | Meaning |
|---|---|
| `systemctl disable --now` | Stop and disable |

**Troubleshoot**

| Symptom | Fix |
|---|---|
| `remove-rich-rule` mismatch | `firewall-cmd --list-rich-rules` then copy exact string |

---

## 🔍 FTP Wrappers Decision Guide

```
Need to block one FTP client IP?
  │
  ├── vsftpd linked to libwrap?
  │     ├── YES
  │     │     └── ✅ hosts.deny line `vsftpd: IP` + allows in hosts.allow
  │     └── NO
  │           └── ✅ firewalld rich rule reject source IP tcp/21
  │
  ├── Need passive mode FTP through NAT?
  │       └── Fix port range + forward — outside wrappers scope
  │
  └── Need auth hardening?
          └── TLS + PAM + strong passwords (other labs)
```

---

## ✅ Lab Checklist (6 Tasks)

- [ ] 01 Install `vsftpd`, capture `rpm -qi` header
- [ ] 02 `systemctl enable --now` + `ss` listener proof
- [ ] 03 `ldd` libwrap check for `/usr/sbin/vsftpd`
- [ ] 04 Write paired `hosts.allow` / `hosts.deny` rules
- [ ] 05 Optional `firewall-cmd` rich rule mirror + reload
- [ ] 06 Remove rich rule, empty hosts.*, disable/remove vsftpd, delete backups

---

## ⚠️ Common Pitfalls

| Mistake | Symptom | Fix |
|---|---|---|
| `systemctl enable vsftpd` typo | Unit not found | Spell `vsftpd` |
| FTP works but wrapper ignored | Policy false sense | Trust `ldd` |
| Passive mode blocked | Data channel hang | Open passive port range in firewall |
| Left vsftpd running | Attack surface | Task 6 disable/remove |
| Rich rule typo | `Invalid port` | Match exact syntax from `--list-rich-rules` |

---

## 🎯 Career & Interview Strategy

**RHCSA candidate**
- Practice **package → unit → socket → policy file** cadence aloud.

**RHCE candidate**
- Role ordering: install → template configs → firewall → handlers `reload`.

**SRE / Platform interview**
- Say: "Cleartext FTP is legacy; if required, **FTPS** + network ACLs."

**DevOps**
- Prefer **S3 + HTTPS** over anonymous FTP for artifact drops.

**AI / MLOps**
- Dataset distribution over FTP should trigger architectural review.

---

## 🔗 Related Labs

| Lab | Connection |
|---|---|
| Lab 68 — Verify TCP Wrappers Support | `ldd` methodology |
| Lab 69 — hosts.deny | Default deny |
| Lab 70 — hosts.allow | Subnet allow patterns |
| Lab 72 — Explore PAM Config Files | AuthZ for real users |

---

## 👤 Author

**Kelvin R. Tobias**
[kelvinintech.com](https://kelvinintech.com) · [GitHub](https://github.com/kelvintechnical) · [LinkedIn](https://www.linkedin.com/in/kelvin-r-tobias-211949219)
