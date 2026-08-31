# Getting Started

A step-by-step setup for running the AI Agent Sandbox connector on your own laptop.

## What you need first

- **Python 3.12 or newer** — check with `python --version`
  (Windows: install from [python.org](https://www.python.org/downloads/) and tick "Add Python to PATH")
- **Git** — to clone the repo
- An AI agent you already use — **Claude Code** is the smoothest fit, but Codex / Cursor / Windsurf work too via MCP

## 1. Get the code

```bash
git clone https://github.com/Boredem125/architecture-mcp.git
cd architecture-mcp
```

## 2. Create a virtual environment (recommended)

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python -m venv .venv
source .venv/bin/activate
```

## 3. Install it

```bash
python -m pip install -e ".[dev]"
```

This installs the package and gives you two commands: `sandbox` and `sandbox-mcp`.

## 4. Check it works

```bash
sandbox --help
python -m pytest -q
```

You should see the command help and **165 passing tests**.

---

## Using the connector on a real project

The connector plugs into **any folder** where you run an AI agent. Say your
project is at `C:\Users\you\myproject`:

### Step 1 — initialize the sandbox in that folder

```bash
cd C:\Users\you\myproject
sandbox init .
```

This creates a `.sandbox/` folder, installs the Claude Code hooks, and writes
an `.mcp.json`. It does **not** touch your code.

### Step 2 — open a terminal to approve requests

Keep this running in its own terminal window:

```bash
sandbox watch .
```

This is where you (the human) approve or deny anything the agent tries that
needs privilege.

### Step 3 — run your agent as normal

In a **different** terminal, in the same folder:

```bash
claude
```

Now use Claude Code however you normally would. The difference:

- Safe commands (`ls`, `git status`, `npm test`) run silently — no interruption
- Anything privileged (installing packages, running arbitrary shell) **pauses**
  and shows up in your `sandbox watch` terminal
- You press **`a`** to approve or **`d`** to deny — the command runs *outside*
  the agent, and its output is handed back so the agent keeps going
- Every file the agent modifies or deletes is saved and restorable

### Try it

Ask Claude: *"Run `whoami` and tell me who I am."*
→ It appears in your watch terminal → press `a` → Claude reports the result.

That's the whole loop.

---

## Handy commands

```bash
sandbox status .          # what's the policy, anything pending?
sandbox changes .         # what files did the agent modify/delete?
sandbox restore app.py .  # undo a change — restore the original
sandbox verify .          # check the audit log hasn't been tampered with
sandbox policy show .      # see the current rules
sandbox uninstall .       # remove the connector (your code is untouched)
```

## Tuning what needs approval

Edit `.sandbox/policy.json`, or use the CLI:

```bash
# let a specific command run without asking
sandbox policy allow-shell "^docker (ps|logs)\b" .

# allow a website for fetches
sandbox policy allow-host api.github.com .

# make reads outside the folder require approval too (stricter)
sandbox policy set-trigger read_outside escalate .
```

---

## Using it with Codex / Cursor / Windsurf (instead of Claude Code)

Those speak **MCP**. When you run `sandbox init .` it writes an `.mcp.json`
already; for Codex, run `sandbox init . --codex` to also print the snippet to
add to `~/.codex/config.toml`. Then in the agent, use the sandbox tools:

- `run_privileged("<command>", "<why>")` — run a privileged command, get output
- `request_path_access("<path>", "write", "<why>", "<content>")` — file ops outside the folder
- `fetch_url("<url>", "<why>")` — fetch a web page through the sandbox

You still keep `sandbox watch .` open to approve them.

---

## Troubleshooting

- **`sandbox: command not found`** — your virtual environment isn't active.
  Re-run the activate command from step 2, or use `python -m sandbox.cli.main` instead.
- **`python` opens the Microsoft Store (Windows)** — Python isn't on PATH.
  Reinstall from python.org with "Add to PATH" ticked, or use the full path.
- **The agent's command just hangs** — you probably don't have `sandbox watch .`
  running in another terminal to approve it. Start it.
- **Nothing gets intercepted** — make sure you ran `sandbox init .` *in the same
  folder* where the agent is running, and that you started the agent *after* init.

Full technical reference: [docs/CONNECTOR.md](docs/CONNECTOR.md)
