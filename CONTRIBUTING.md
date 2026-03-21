# Contributing to Discoverykastle

Thank you for your interest in contributing. Please read this guide before submitting a pull request.

---

## Development Setup

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker 24+ and Docker Compose 2.20+
- `uv` (Python package manager — recommended) or `pip`
- `nvm` (Node version manager — recommended)

### Local Setup

```bash
# Clone the repo
git clone https://github.com/tunisiano187/Discoverykastle.git
cd Discoverykastle

# Server setup
cd server
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Frontend setup
cd ../server/frontend
npm install

# Agent setup
cd ../../agent
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Start dev environment
cd ..
cp .env.example .env
docker compose -f docker-compose.dev.yml up -d
```

### Running Tests

```bash
# Server tests
cd server && pytest

# Agent tests
cd agent && pytest

# Frontend tests
cd server/frontend && npm test

# All tests (from repo root)
make test
```

---

## Branch Naming

Branches must follow this convention:

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/<short-description>` | `feat/agent-ssh-probe` |
| Bug fix | `fix/<short-description>` | `fix/cve-duplicate-entries` |
| Docs | `docs/<short-description>` | `docs/deployment-guide` |
| Refactor | `refactor/<short-description>` | `refactor/task-engine` |
| Security fix | `security/<short-description>` | `security/patch-auth-bypass` |
| Chore | `chore/<short-description>` | `chore/upgrade-dependencies` |

---

## Code Style

### Python (Server and Agent)

- **Formatter**: `black` (line length: 100)
- **Linter**: `ruff`
- **Type hints**: required for all public functions and methods
- **Docstrings**: Google style, required for all public classes and functions

```bash
# Format and lint
black .
ruff check . --fix
```

Pre-commit hooks enforce this automatically. Install them:

```bash
pip install pre-commit
pre-commit install
```

### JavaScript / TypeScript (Frontend)

- **Formatter**: `prettier`
- **Linter**: `eslint`
- **TypeScript**: strict mode required

```bash
cd server/frontend
npm run lint
npm run format
```

---

## Pull Request Requirements

Before opening a PR, ensure:

- [ ] All tests pass (`make test`)
- [ ] No linting errors
- [ ] New code has tests (minimum 80% coverage for new modules)
- [ ] Documentation is updated if behavior changes
- [ ] Commit messages follow the Conventional Commits format (see below)
- [ ] No secrets, credentials, or personally identifiable information in code or tests

### Conventional Commits

```
<type>(<scope>): <short summary>

<optional body>

<optional footer>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `security`

Examples:
```
feat(agent): add Juniper JunOS SSH probe support
fix(server): prevent task dispatch outside authorized CIDR
docs(security): add mTLS certificate renewal procedure
security(agent): validate task target against scope before execution
```

---

## Security Vulnerability Reporting

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately via GitHub's Security Advisory feature:
`https://github.com/tunisiano187/Discoverykastle/security/advisories/new`

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- (Optional) Suggested fix

We aim to acknowledge all reports within 48 hours and provide a fix timeline within 7 days.

---

## Project Structure

```
Discoverykastle/
├── server/
│   ├── api/           # FastAPI routes
│   ├── core/          # Business logic services
│   ├── db/            # SQLAlchemy models and migrations
│   ├── tasks/         # Background task workers
│   ├── vault/         # Credential vault
│   ├── ca/            # Certificate Authority
│   ├── docs_builder/  # Infrastructure documentation generator
│   ├── frontend/      # React application
│   └── tests/
├── agent/
│   ├── core/          # Agent core, comms, task executor
│   ├── modules/
│   │   ├── host/      # Host enumeration
│   │   ├── security/  # CVE analysis
│   │   ├── network/   # Interface enum, nmap
│   │   └── devices/   # Network device probing
│   └── tests/
└── docs/
```

---

## Questions?

Open a [GitHub Discussion](https://github.com/tunisiano187/Discoverykastle/discussions) for general questions and ideas.
