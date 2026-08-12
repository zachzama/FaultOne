# Security

## Reporting something

Use **Security → Report a vulnerability** on this repository, which opens a
private advisory visible only to you and the maintainer. Please don't open a
public issue for anything exploitable — a diagnostic that runs commands on
other people's infrastructure is a bad place for a public zero-day.

Include what you ran, what happened, and what you expected. A report that
reproduces is worth more than one that theorises.

## What is supported

The latest release. There is one file and no branches to back-port to, so a
fix ships as the next version rather than as a patch to an older one.
`python3 faultone.py --version` says what a box is carrying, and every report
records the version that produced it.

## What this tool does, so you can judge the surface

- **It never opens a port and never listens.** There is no server, no agent
  and no daemon. Nothing here accepts input from the network.
- **It runs real commands with your privileges** — the ones you would run by
  hand, as an argv list and never through a shell. It reads counters, sends
  pings and traceroutes, and opens TCP connections to targets you name.
- **It has no dependencies.** Only the standard library, so nothing is vendored
  and no third-party code travels with the file.
- **Optional tools are used if present** (`mtr`, `ethtool`, `lldpd`,
  `tcptraceroute`) and are run as separate programs, never linked or imported.

## Reports are sensitive

A report is a **map of the network it was taken on**: internal addressing, MAC
addresses, switch names, VLANs, resolvers and listening ports. Exports are
written `0600` for that reason.

Treat one like a network diagram — fine in a ticket, fine with the people who
own that network, not committed to a repository or pasted somewhere public.
`.gitignore` here covers `report.json` and `report.html`, but it cannot know
what you named yours.

If you are sending a report to support a vulnerability report, redact it or
send the smallest thing that reproduces the problem.

## Not vulnerabilities

- A finding you disagree with, or a verdict that names the wrong cause. That
  is a bug and belongs in a normal issue — the tool applies one plausible
  ordering and says *likely* for exactly this reason.
- The tool reading system state it has permission to read.
- Output containing your own network's details. That is the product; see above.
