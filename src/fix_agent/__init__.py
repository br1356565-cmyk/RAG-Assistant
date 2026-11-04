"""Fix agent: drafts a dependency upgrade for a Dependabot finding, pauses for a team lead's
approval (LangGraph interrupt), and only then opens a pull request through the Gateway's
write tool. Runs on AgentCore Runtime as an A2A server; the audit agent delegates to it."""
