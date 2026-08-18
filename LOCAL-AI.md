# The local AI companion

A model running on your own machine, watching the same telemetry you are.

It is **optional**. Everything else in AEGIS works without it.

---

## Why this exists separately from the AI Analyst tab

They are not the same feature and it is worth being clear about which you want.

| | **AI Analyst** tab | **Companion** |
|---|---|---|
| Model | Claude, via Anthropic | Whatever you run locally |
| Needs | API key + internet | Nothing but the host |
| Who starts | You type a question | It reads telemetry and speaks first |
| Good at | Deep analysis, writing detections, long reasoning | Fast triage opinions, continuous, cheap |
| Air-gapped | No | Yes |

The Analyst waits to be asked, which is fine when you already know the question.
During an incident at 3am you often don't — you have forty events and no idea
whether they matter. That is the gap this fills.

Run both. They cost nothing when idle.

---

## Setup — two commands

### 1. Install a local inference server

**Ollama** is the easiest and pulls models straight from Hugging Face.

| | |
|---|---|
| **Windows** | `winget install Ollama.Ollama` |
| **macOS** | `brew install ollama` |
| **Linux** | `curl -fsSL https://ollama.com/install.sh \| sh` |

Or download it from <https://ollama.com/download>.

> AEGIS does **not** install this for you. Running someone else's installer from
> inside a script is the supply-chain problem this tool exists to help you
> detect, so it prints the command and lets you run it deliberately.

Already have **LM Studio**, **llama.cpp**, **Jan**, **vLLM** or **TGI**? Skip
this step — AEGIS speaks to all of them and will find whichever is running.

### 2. Point AEGIS at it

```bash
npm run ai:setup
```

That finds the runtime, pulls a model if you have none, writes the config, and
verifies the whole path by asking it a real question. Then restart AEGIS.

That's it.

---

## What it does once it's running

A **◈ Companion** button appears in the top bar.

**It speaks first.** When suspicious or malicious telemetry lands, it reads it
and posts an assessment without being asked — tagged `UNPROMPTED`, with the
event count and the hosts involved:

> **UNPROMPTED · 41 EVENTS · DC01**
> This is a password-spray burst against DC01 — 40 failed logons (4625) inside a
> minute from one source, followed by a success. Treat as likely compromise.
> Next: pull 4624 for that account and check the source IP against your VPN pool.

**You can also just ask it.** Type into the panel. It keeps a short thread.

Three things stop it becoming noise:

- it only wakes for events worth waking for, not every heartbeat,
- it debounces, so a storm of 200 events produces one assessment rather than 200,
- it will not queue up: a slow model means fewer opinions, never a backlog.

Turn the unprompted half off and keep the ask-it-yourself half:

```json
"llm": { "watch": false }
```

---

## Choosing a model

The default is **Llama 3.2 3B** at Q4 (`hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M`),
about 2GB.

That is a deliberate choice, not a shortcut. The companion writes two or three
sentences about a burst of telemetry, many times an hour, on whatever hardware
the SOC actually has. A 3B at Q4 runs on a laptop with no GPU, answers in a
couple of seconds, and is entirely good enough to say *"that's Kerberoasting,
check 4769 for RC4"*. A 70B would be better at it and would also make the
feature unusable on most of the machines it will run on.

If you have the hardware, use more:

```bash
npm run ai:setup -- --bigger                                        # Qwen2.5 7B
npm run ai:setup -- --model hf.co/bartowski/Qwen2.5-14B-Instruct-GGUF:Q4_K_M
```

Any GGUF on Hugging Face works via the `hf.co/` prefix.

| Model size | RAM | Feels like |
|---|---|---|
| 3B Q4 | ~4 GB | Instant. Good triage instincts, occasionally shallow. |
| 7–8B Q4 | ~8 GB | A second or two. Noticeably better reasoning. The sweet spot if you have the RAM. |
| 14B Q4 | ~12 GB | Several seconds. Better again; check it still feels live. |

---

## Air-gapped networks

This works with no internet at all — that is much of the point.

1. On a machine with internet: `ollama pull <model>`
2. Copy `~/.ollama/models` (Windows: `%USERPROFILE%\.ollama\models`) across.
3. Install Ollama on the far side, drop the models directory in, start it.
4. `npm run ai:setup`

Nothing in this path reaches the network at run time. The model sees your
telemetry; nothing else does.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Button says **Local AI**, greyed | Nothing running. `npm run ai:check` to see what AEGIS can find. |
| First answer takes 30s+ | Normal — the first request loads the weights. Subsequent ones are fast. |
| *"took too long"* | Model too big for the RAM, or still loading. Try a smaller one. |
| Nothing unprompted appears | `"watch"` is off, or nothing suspicious has landed. Only suspicious/malicious wake it. |
| Answers are vague | Expected below ~7B on hard questions. Use `--bigger`, or ask the AI Analyst tab. |

Check what the server sees:

```bash
curl http://127.0.0.1:8787/api/llm/status -H "Authorization: Bearer <analyst-token>"
```

Started Ollama after AEGIS? Nothing needs restarting — hit `/api/llm/detect` or
just reconnect the console.

---

## Privacy

Your telemetry goes to a process on your own machine and nowhere else. There is
no account, no key, no usage reporting, and no network call in this path at all.

The one thing worth knowing: the companion is shown a **compact summary** of
recent events — timestamps, hosts, event IDs, severities, technique tags and
truncated messages. Forty identical failed logons become one line with a count,
which is both what a small model needs and what a person would want to read.
