"""LLM Adversary Lab — orchestrator package.

The only bespoke code in the lab. A small, modular ReAct agent that drives a local
LLM against an isolated, deliberately-vulnerable target through a logged execution
channel, with a pure scope/safety guard in front of every command.

See the README and docs/architecture.md.
"""

__version__ = "0.1.0"
