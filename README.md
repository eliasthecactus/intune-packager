# Intune Packager

> **Disclaimer:** AI was used heavily in this project.

Web app that turns installers, scripts or just a product description into a ready-to-upload
**Intune Win32 app**. An AI agent analyses the files, researches silent parameters on the web and
returns a zip with:

- `<App>-<Version>.intunewin`: built natively, same format as Microsoft's IntuneWinAppUtil
- install and uninstall commands, install behavior, restart behavior, return codes
- detection rules (MSI, file, registry or a `detect.ps1` script) and requirements
- generated wrapper scripts (`install.ps1` / `uninstall.ps1`) when they are needed
- `logo.png`, taken from the installer icon or the vendor's logo
- `README.md` with every Intune portal field, notes, warnings, open points and sources
- `intune-app.json` with the same data in machine-readable form

If a silent deployment isn't possible, the app says so, explains why and lists what would be needed.

## Quick start (Docker)

A prebuilt image for amd64 and arm64 is published to `ghcr.io/eliasthecactus/intune-packager`. Pick one of the
commands below, fill in your key and open http://localhost:8000. `SHARED_KEY` is optional but recommended as soon
as anyone else can reach the port. All other settings from [.env.example](.env.example) can be added with more `-e`
flags.

**OpenRouter**

```bash
docker run -d --name intune-packager -p 8000:8000 \
  -v intune-packager-data:/data --restart unless-stopped \
  -e LLM_PROVIDER=openrouter \
  -e OPENROUTER_API_KEY=sk-or-... \
  -e OPENROUTER_MODEL=deepseek/deepseek-v4.1-flash \
  -e SHARED_KEY=change-me \
  ghcr.io/eliasthecactus/intune-packager:latest
```

**Microsoft Foundry with DeepSeek**

```bash
docker run -d --name intune-packager -p 8000:8000 \
  -v intune-packager-data:/data --restart unless-stopped \
  -e LLM_PROVIDER=foundry \
  -e FOUNDRY_RESOURCE=my-foundry-resource \
  -e FOUNDRY_API_KEY=... \
  -e FOUNDRY_MODEL=DeepSeek-V4.1-Flash-1017 \
  -e SHARED_KEY=change-me \
  ghcr.io/eliasthecactus/intune-packager:latest
```

**Microsoft Foundry with ChatGPT**

```bash
docker run -d --name intune-packager -p 8000:8000 \
  -v intune-packager-data:/data --restart unless-stopped \
  -e LLM_PROVIDER=foundry \
  -e FOUNDRY_RESOURCE=my-foundry-resource \
  -e FOUNDRY_API_KEY=... \
  -e FOUNDRY_MODEL=gpt-6.1-sol \
  -e SHARED_KEY=change-me \
  ghcr.io/eliasthecactus/intune-packager:latest
```

For Foundry, `FOUNDRY_RESOURCE` is the `<name>` in `https://<name>.services.ai.azure.com` and `FOUNDRY_MODEL` is
the name of your deployment, so use whatever you named it in the Foundry portal. GPT deployments use the Responses
API and DeepSeek deployments use chat completions, picked automatically from the name (see [AI provider](#ai-provider)).

To build it yourself instead:

```bash
cp .env.example .env        # add your AI provider key, optionally SHARED_KEY
docker compose up -d --build
```

## Quick start (local)

Requires Python 3.12 or newer, `7zz`/`7z`, `msitools` and optionally `innoextract`. On macOS: `brew install sevenzip msitools innoextract`.

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a; source .env; set +a
.venv/bin/uvicorn app.main:app --port 8000
```

## AI provider

Choose the provider with `LLM_PROVIDER`.

| Provider | Variables | Notes |
|---|---|---|
| `openrouter` | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` (default `deepseek/deepseek-v4.1-flash`) | Any OpenRouter model that supports tool calling |
| `foundry` | `FOUNDRY_RESOURCE` or `FOUNDRY_ENDPOINT`, `FOUNDRY_API_KEY`, `FOUNDRY_MODEL` (deployment name, default `claude-opus-5-5`) | The API is picked from the deployment name, see below. |

On Foundry, `FOUNDRY_API_STYLE=auto` picks the API from the deployment name:

| Deployment name | API |
|---|---|
| `claude-*` | Anthropic Messages API through the official `anthropic` SDK (`AnthropicFoundry`) |
| `gpt-*`, `o3*`, `o4*`, `codex-*` | OpenAI Responses API (`/openai/v1/responses`). Reasoning is kept between tool calls, and some models such as the codex and pro models only work here. |
| anything else (DeepSeek, Llama, Mistral, Grok, …) | Chat completions (`/openai/v1/chat/completions`) |

If you named a deployment differently, set `FOUNDRY_API_STYLE=anthropic`, `responses` or `chat` yourself.

Optional Foundry settings:

- `FOUNDRY_FALLBACK_MODEL`: a second deployed Claude model that takes over if the main model refuses a request.
- `FOUNDRY_AUTH_HEADER=bearer`: for OpenAI-style endpoints that expect `Authorization: Bearer`.
- `FOUNDRY_API_VERSION`: only for legacy endpoints that still need it.

`CLAUDE_EFFORT` (default `high`) sets the effort level for Claude models. `OPENAI_REASONING_EFFORT` does the same
for OpenAI models on the Responses API (empty = model default).

## Access protection

If `SHARED_KEY` is set, users must enter the key before they can use the app. After login the session lives in an
HttpOnly, SameSite=Strict cookie. API clients can send `X-Access-Key: <key>` instead. Failed logins are slowed down
and limited per IP address. Without `SHARED_KEY` the app is open to everyone who can reach it.

Put the app behind HTTPS (reverse proxy) when it is reachable from other machines. The proxy must allow large
request bodies, e.g. `client_max_body_size 4g;` in nginx, and long timeouts for uploads.

## Web research

With `SEARCH_PROVIDER=auto` the app uses the first configured provider in this order:
Tavily (`TAVILY_API_KEY`), Brave (`BRAVE_API_KEY`), SearXNG (`SEARXNG_URL`), DuckDuckGo.
DuckDuckGo needs no key but often rate-limits servers, so for regular use configure one of the others.

The agent can read web pages and download installers and logos, over https only. Requests to private or internal
addresses are blocked (SSRF protection) unless `ALLOW_PRIVATE_URLS=true`.

## How it works

1. Uploads are stored per job, and folder structure is preserved.
2. Static analysis runs; **files are never executed**:
   - PE version info, architecture, signature, manifest
   - installer framework detection (Inno, NSIS, WiX Burn, InstallShield, InstallAnywhere, Squirrel, …) with silent-switch hints
   - MSI properties and tables, MSIX manifest, archive listings
   - icon extraction
3. The agent works with tools. It can:
   - inspect files, extract archives and self-extractors, query MSI tables and search strings
   - search the web, read pages and download files
   - write wrapper scripts into the package, copy extracted files into it and delete junk
   - choose a logo
4. It calls `finish` with a structured result. The server validates it (setup file exists, commands without
   placeholders, detection rules complete) and sends problems back to the AI to fix.
5. The server builds the `.intunewin`, renders the README and zips everything. Uploaded and extracted files are
   deleted after the job, and results expire after `JOB_TTL_HOURS`.

## Limits and settings

| Variable | Default | |
|---|---|---|
| `MAX_UPLOAD_MB` | 4096 | Max. upload per job |
| `DOWNLOAD_MAX_MB` | 2048 | Max. size of files the AI downloads |
| `MAX_CONCURRENT_JOBS` | 2 | Further jobs wait in a queue |
| `AGENT_MAX_STEPS` | 60 | AI tool-call rounds per job |
| `JOB_TTL_HOURS` | 24 | Results are deleted afterwards |
| `DATA_DIR` | `./data` (`/data` in Docker) | Job storage |

Jobs are kept in memory, so a restart forgets running and finished jobs.

## Security notes

- Uploaded files and web content go to the configured AI provider as text: analysis results, file contents and
  page text. Do not upload anything that must not leave your environment.
- File contents and web pages could contain prompt-injection attempts. The agent is told to treat them as data. Its
  tools only work inside the job folder, and web access is limited to public https URLs. Still, **review the
  generated scripts before you deploy them.**
- Every result is AI-generated. Test it on a pilot device before deploying broadly.

## License

[MIT](LICENSE)
