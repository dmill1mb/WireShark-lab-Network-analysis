# Lab 2 — Wireshark & Network Analysis

**Wireshark (Free) · Local Machine or Azure VM · Network Analysis**

| Field | Value |
|---|---|
| Certification alignment | CompTIA Network+ · Security+ · CySA+ |
| Free tools | Wireshark — free and open source, no expiration, no account required |
| Time to complete | 2–4 hours across multiple sessions |
| Estimated cost | $0 — Wireshark is permanently free |
| Career relevance | Network Engineer · SOC Analyst · Cloud Security Engineer · Incident Responder |

---

## Why this lab matters

Networks carry every piece of data an organisation produces — emails, database queries, login credentials, file transfers, API calls. When something goes wrong — a service is unreachable, a user reports slow performance, a security alert fires — the network is almost always involved. The only way to know what's actually happening is to look at the packets.

Wireshark is the tool organisations use to do that. It captures the raw data moving across a network interface and lets you inspect it at every layer, from the physical frame up to the application payload.

| Role | How this lab applies |
|---|---|
| Network Engineer | Diagnose connectivity issues by seeing exactly where packets are dropped or delayed |
| SOC Analyst | Identify malicious traffic patterns, extract indicators of compromise from packet captures |
| Cloud Security Engineer | The mental model from Wireshark transfers directly to reading Azure Network Watcher and VPC flow logs |
| Help Desk | Prove that a reported network issue is real and identify whether it's client-side or server-side |

## What you'll learn

| Skill | Real-world application |
|---|---|
| Capture live network traffic | The foundational skill — you cannot analyse what you cannot see |
| Apply display filters | Production captures generate millions of packets; filters find the 10 that matter in seconds |
| Read TCP handshakes | Recognising a normal three-way handshake versus an incomplete one tells you immediately whether a connection succeeded or failed |
| Identify DNS queries and responses | DNS is involved in virtually every network action — this mental model transfers directly to cloud DNS troubleshooting |
| Spot cleartext credentials in HTTP | A hands-on demonstration of why HTTPS matters |
| Follow TCP streams | Reassemble the full conversation between two hosts from individual packets — essential for incident investigation |

---

## Architecture — how Wireshark captures traffic

![Lab 2 architecture diagram](file:///C:/Users/demar/Downloads/lab2-wireshark-architecture.svg)

Your browser and terminal generate traffic the normal way — an HTTP request, an `nslookup` query — and that traffic passes through your network interface card on its way out to the router and onward across the internet to a DNS server or web server. Wireshark doesn't sit *in* that path. It puts the NIC into **promiscuous mode**, which hands Wireshark a mirrored copy of every frame crossing that interface, while the original traffic continues on its way unaffected. That's why you can capture and inspect traffic without disrupting the connection it belongs to — Wireshark is observing, not intercepting.

---

## Key concepts — read this before starting

These come up constantly throughout the lab. Read through them now so the steps make sense as you go.

**What is a packet?** A small unit of data that travels across a network. When you load a web page, the data doesn't travel as one piece — it's broken into hundreds or thousands of smaller packets, each with a header (source IP, destination IP, port number) and a payload (the actual data). Packets travel independently, potentially taking different routes, and get reassembled at the destination. Wireshark captures and shows you each one individually.

**What is a network protocol?** A set of rules defining how data is formatted and transmitted. DNS translates domain names into IP addresses. HTTP transfers web page content. TCP ensures packets are delivered reliably. ICMP handles ping and diagnostics. Each protocol has its own port number and packet structure — in Wireshark you filter by protocol to isolate the traffic you care about.

**What is the TCP three-way handshake?** Before two computers exchange data over TCP, they perform a three-step setup. Step 1 — your machine sends **SYN**: "I want to connect." Step 2 — the server responds **SYN-ACK**: "Received, here's my acknowledgement." Step 3 — your machine sends **ACK**: "Confirmed, ready to send data." A SYN with no SYN-ACK means the connection was refused or the server is unreachable — one of the most useful signals when diagnosing connectivity problems.

**What is DNS?** The system that translates domain names (`google.com`) into IP addresses (`142.250.80.46`). Every website visit, app launch, or email send triggers a DNS query first. A query asks "what's the IP for this domain?" and the response contains the answer. If DNS is broken, nothing works — no websites, no database connections, no email delivery.

**What is HTTP vs HTTPS?** HTTP transfers web content unencrypted — anyone who can see the traffic can read every request and response, including usernames and passwords typed into login forms. HTTPS adds TLS encryption on top, so even a captured packet can't be read by anyone without the decryption key. In this lab you'll see cleartext credentials in an HTTP capture — that demonstration is exactly why HTTPS became the standard for anything handling sensitive data.

**What is promiscuous mode?** Normally a NIC only captures packets addressed to your machine. In promiscuous mode it captures *every* packet on the network segment, including ones addressed to other machines. Wireshark enables this automatically when you start a capture. On a switched network (most modern networks), you'll mainly see your own traffic plus broadcast traffic. On older hub-based networks, or with port mirroring configured, you can see everything on the segment.

---

## Step 1 — Install Wireshark

Wireshark is completely free and open source. Go to `wireshark.org/download.html` and download the installer for your OS — no account, no trial, no licence.

| OS | Download | Notes |
|---|---|---|
| Windows | Windows x64 Installer (.exe) | Accept all defaults. Install **Npcap** when prompted — required to capture packets |
| macOS | macOS Arm or Intel (.dmg) | If prompted about **ChmodBPF**, allow it — this grants Wireshark permission to access network interfaces |
| Linux | Use your package manager | `sudo apt install wireshark` (Ubuntu/Debian). Add yourself to the `wireshark` group to capture without root |

```bash
# Linux only — add yourself to the wireshark group (log out and back in after)
sudo usermod -aG wireshark $USER

# Verify Wireshark is installed
wireshark --version
```

---

## Step 2 — Your first capture

This step gets you comfortable with the interface before doing anything complex.

1. Open Wireshark — the welcome screen lists network interfaces with wavy lines showing live activity
2. Double-click your active interface (Ethernet or Wi-Fi — pick the one with the most wave activity)
3. Capture starts immediately — packets appear in the list in real time
4. Open a browser and navigate to any website
5. After 30 seconds, click the red square **Stop** button in the toolbar

You now have a packet capture in memory — every frame that crossed that interface during the window. The volume can be overwhelming, even from 30 seconds of browsing. That's exactly why display filters exist.

---

## Step 3 — Essential display filters

Type filters into the filter bar at the top of the window and press Enter. The packet list updates instantly to show only matching traffic — this is one of the most important skills in the lab.

**Display filters vs. capture filters.** Capture filters apply *before* capturing and limit what gets recorded. Display filters apply *after* capturing and limit what you see without discarding anything. For this lab, always use display filters — apply `dns`, look at DNS traffic, remove it and apply `tcp` to look at something else, and the full capture is always there underneath.

| Filter | What it shows | When to use it |
|---|---|---|
| `dns` | All DNS queries and responses | Troubleshooting name resolution, spotting unusual domain lookups |
| `http` | Unencrypted HTTP traffic only | Finding cleartext data, debugging web apps without HTTPS |
| `tcp` | All TCP traffic | Starting point for connectivity investigations |
| `tcp.flags.syn == 1` | TCP SYN packets — connection attempts | Seeing which hosts are trying to connect to what |
| `tcp.flags.reset == 1` | TCP RST packets — connection resets | Finding refused or forcibly closed connections |
| `icmp` | All ICMP traffic including ping | Verifying basic reachability between hosts |
| `ip.addr == 192.168.1.1` | All traffic to or from a specific IP | Isolating traffic for a single host in a busy capture |
| `ip.src == 10.0.0.5` | Traffic from a specific source IP only | Isolating outbound traffic from one host |
| `tcp.port == 443` | All HTTPS traffic | Identifying encrypted web traffic by port |
| `http.request` | HTTP GET and POST requests only | Finding web requests — useful for spotting data exfiltration |

---

## Step 4 — Guided exercises

Work through each exercise in order — each builds on the previous and teaches a specific skill used in real-world network analysis.

### Exercise A — Capture a DNS lookup

**What is `nslookup`?** A built-in command-line tool that manually performs a DNS lookup — give it a domain name, it tells you the IP address DNS returns. It's useful here because it lets you trigger a DNS query on demand, which is exactly the traffic you want Wireshark to capture.

Run `nslookup` on your local machine, **not** inside Wireshark — Wireshark has no terminal, it's purely a capture and analysis tool. The workflow is: start a capture in Wireshark, switch to a separate terminal window, run the command, then come back and stop the capture. Wireshark will have recorded the DNS traffic `nslookup` generated.

**Opening a terminal:** Windows — press the Windows key, type `cmd`, press Enter. Mac — press `Cmd + Space`, type `Terminal`, press Enter. Linux — right-click the desktop → *Open Terminal*, or `Ctrl + Alt + T`.

**What is a DNS A record?** DNS has different record types for different jobs. An **A record** maps a domain name to an IPv4 address — the most common type. When you type `google.com` into a browser, your computer queries for the A record, and the response contains the IPv4 address to connect to. Other types exist: AAAA (IPv6), MX (mail servers), CNAME (aliases). In Wireshark, the record type appears as a number — type 1 is an A record.

**Steps:**

1. In Wireshark, start a capture on your active interface (blue shark fin icon, or double-click the interface name)
2. Leave Wireshark running and open a separate terminal window
3. In the terminal, run:
   ```bash
   nslookup google.com
   ```
4. The terminal shows the IP address(es) returned for `google.com` — confirms the lookup worked
5. Switch back to Wireshark and click **Stop**
6. In the filter bar, type `dns` and press Enter — the list now shows only DNS traffic
7. Find the query packet — look in the Info column for *"Standard query A google.com"* — this is your machine asking for the A record
8. Find the response packet — *"Standard query response A google.com"* — this contains the IP address the DNS server returned
9. Click the response packet. In the packet detail pane, expand **Domain Name System (response)** → look in the **Answers** section for the A record and IP address. Confirm it matches what your terminal showed.

**What you just saw:** your machine sent a DNS query for the A record of `google.com`, the DNS server replied with an IP, and your browser used that IP to make the actual connection. This invisible lookup happens before every website visit, API call, and email your machine sends. In the real world, unexpected DNS queries to unusual domains in a capture are often the first sign of malware calling home to a command-and-control server.

### Exercise B — Watch the TCP three-way handshake

1. Start a capture on your active interface
2. Open a browser and navigate to `http://example.com` — HTTP, not HTTPS, makes the handshake easier to see
3. Stop the capture
4. Run `nslookup example.com` first to get the IP address, then apply the filter `tcp and ip.addr == [that IP]`
5. Find three packets in order: SYN → SYN-ACK → ACK

| Packet | Flags | What it means |
|---|---|---|
| 1st | SYN | Your machine: "I want to connect. Here's my sequence number." |
| 2nd | SYN, ACK | The server: "Got your request. Here's mine. Connection accepted." |
| 3rd | ACK | Your machine: "Got it. Connection open, ready to send data." |

A SYN with no following SYN-ACK means the connection was refused or the server is unreachable. A RST packet means the connection was forcibly closed. These two patterns are the most common things network engineers look for when diagnosing connectivity problems.

### Exercise C — Spot cleartext credentials (HTTP)

> **Educational exercise only.** Only capture on networks and against systems you own or have explicit permission to analyse. Never use this technique against systems you don't own.

1. Set up a test HTTP login form locally, or use a test site running over HTTP (not HTTPS)
2. Start a capture
3. Submit the login form with a test username and password
4. Stop the capture
5. Apply the filter `http.request.method == POST`
6. Click the POST packet, and in the packet detail pane look for the **HTML Form URL Encoded** layer
7. The username and password appear in plaintext

This is why every login form must use HTTPS. Without TLS encryption, anyone on the network path between you and the server — an ISP, a coffee shop router, anyone running a man-in-the-middle attack — can read credentials exactly as typed. Wireshark is how security teams prove this vulnerability exists and demonstrate it to developers who resist adding HTTPS.

### Exercise D — Follow a full TCP stream

1. Capture any HTTP traffic by navigating to an HTTP website
2. Find any HTTP packet in the capture list
3. Right-click it → **Follow → TCP Stream**
4. Wireshark reassembles all the packets from that connection into a readable conversation — red text is your browser's request, blue is the server's response

This is how incident responders reconstruct what happened during a network event. Individual packets are fragments — the stream view shows the complete conversation: what data was transferred, what commands were sent, what the server responded with.

---

## Step 5 — Save and export captures

Always save interesting captures — they're evidence of your skills and your portfolio entries for this lab.

```bash
# Save a capture for later analysis
File → Save As → choose .pcapng format

# Export only the packets matching your current filter
# Apply your display filter first, then:
File → Export Specified Packets → Displayed

# Re-open a saved capture
File → Open → select your .pcapng file

# Command-line capture with tshark (included with Wireshark — useful for remote servers)
tshark -i eth0 -w capture.pcapng -c 1000
# -i: interface name   -w: output file   -c: stop after this many packets
```

---

## Verification — confirm the lab is working

| Skill | How to verify |
|---|---|
| DNS capture | Apply the `dns` filter and identify a query packet and its response — they should share matching transaction IDs |
| TCP handshake | Find three sequential packets with SYN, SYN-ACK, and ACK flags — explain what each means without referring to notes |
| Display filters | Filter by IP address, port, and protocol from memory — no lookup needed |
| Stream reconstruction | Follow a TCP stream and read the full HTTP request/response as a conversation |
| File management | Save a capture, close Wireshark, reopen it, and load the file — confirm all packets are there |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No interfaces shown, or no traffic on any interface | On Windows, confirm Npcap installed correctly during setup — reinstall Wireshark and make sure the Npcap checkbox is ticked. On Mac, confirm ChmodBPF was allowed during install |
| "You don't have permission to capture" (Linux) | You weren't added to the `wireshark` group, or you haven't logged out and back in since running `usermod -aG wireshark $USER`. Log out fully and back in, then retry |
| Capture shows almost no traffic | You may be on a switched network seeing only your own traffic plus broadcasts — this is normal and expected, not a misconfiguration. To see other hosts' traffic you'd need port mirroring configured on a managed switch |
| `nslookup` traffic doesn't appear in the `dns` filter | Confirm you ran `nslookup` *after* starting the capture, not before. DNS responses can also be served from a local resolver cache — try a domain you haven't queried recently |
| No SYN-ACK after the SYN packet | The server is unreachable, the port is filtered by a firewall, or the service isn't listening on that port. This is a real connectivity diagnosis, not a capture error |
| Can't find the POST data in Exercise C | Confirm the form actually submitted over HTTP, not HTTPS — most modern test sites redirect to HTTPS automatically, which will encrypt the body and defeat the exercise |

---

## Documentation checklist

Before you close this lab out, capture it for your portfolio:

- [ ] Saved `.pcapng` of the DNS lookup (Exercise A)
- [ ] Saved `.pcapng` of the TCP three-way handshake (Exercise B)
- [ ] Saved `.pcapng` or screenshot of a followed TCP stream (Exercise D)
- [ ] Upload all three to a GitHub repo with a README describing what each capture shows and what you learned from it

This is concrete evidence of network analysis skills to show in interviews.

---

## Reflection

**What surprised me**

I went into Exercise C already knowing, intellectually, that HTTP sends data in plaintext. I'd read that fact a dozen times in study material. It didn't actually land until I submitted a test login form, applied `http.request.method == POST`, and watched the username and password sitting right there in the HTML Form URL Encoded layer — not obscured, not encoded, just readable text exactly as I'd typed it. There's a real gap between knowing a fact and seeing the evidence yourself, and this lab closed that gap in about thirty seconds. It also reframed how I think about every "just use HTTP for the internal tool, it's faster" conversation I'll inevitably hear on the job. Internal doesn't mean safe — it means fewer people happen to be watching, not that no one can.

**What I'd do differently at enterprise scale**

Running Wireshark by hand on a single interface is the right way to learn the protocols, but it isn't how monitoring actually works at scale. A few things would have to change in a real environment.

Packet captures would need to be scoped and governed, not casual. Capturing live traffic on a corporate network touches employee data and, depending on jurisdiction, can run into wiretapping or privacy law. Before any capture happens in production, there needs to be a documented authorization — what's being captured, why, for how long, and who has access to the resulting file. I wouldn't run an unscoped capture on a shared segment without that sign-off in place.

Manual packet inspection also doesn't scale as a monitoring strategy. You can't run Wireshark on every endpoint and read packets all day. Enterprises use SPAN/mirror ports or network taps feeding into centralized tools — IDS/IPS platforms, Zeek, NetFlow collectors — that flag anomalies automatically, and packet capture gets reserved for the deep-dive investigation once something's already been flagged. Wireshark is the scalpel, not the daily monitoring tool.

And the HTTP exercise would translate into an actual policy position: no application serving anything beyond a fully isolated test environment should be allowed to run unencrypted. That's not a suggestion to developers, it's a network-level control — TLS termination enforced at the load balancer, internal service mesh encryption, certificates managed centrally rather than left to individual teams to bolt on later.

**How this maps to the sysadmin role I'm targeting**

This lab is the other half of what I started with the Active Directory lab. AD answers "who is allowed to do what." Wireshark answers "what is actually happening on the wire right now." A sysadmin gets paged with "the app is slow" or "I can't reach the server" far more often than with a clean, well-described bug report, and the difference between guessing and diagnosing is being able to open a capture and show, with packets, whether the problem is DNS resolution failing, a TCP handshake never completing, or the application itself responding slowly after a perfectly healthy connection. That's not a theoretical skill — it's the difference between telling a user "try restarting your computer" and telling them exactly what's broken and why.

It also gives me a concrete, defensible answer to an interview question I used to dread: "how would you troubleshoot a connectivity issue?" Now I can walk through it — check the handshake, check DNS, check whether traffic is even reaching the interface — instead of describing it in the abstract.
