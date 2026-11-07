# bw2fabroker

A small Go broker in front of the Bitwarden CLI. An agent asks for one field of one item. You approve
it on your phone (push from your own ntfy domain, approval page on your tailnet, approval password).
The broker returns that one value once, in a fixed JSON shape; nothing else passes to the agent.

- Plan: [docs/DEV_PLAN.md](docs/DEV_PLAN.md)
- Agent skill: [skills/bw-broker/SKILL.md](skills/bw-broker/SKILL.md)

Status: planning.
