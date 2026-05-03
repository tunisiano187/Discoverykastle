# Discoverykastle — Claude Code Instructions

## Règles de workflow

### PR toujours ouverte
**Tant qu'il reste des tâches à faire (ROADMAP.md ou todo list), il doit toujours y avoir une PR ouverte sur GitHub.**

Après chaque session de travail :
1. Committer les changements sur la branche de travail (`claude/<feature>-<id>`)
2. Pusher la branche : `git push -u origin <branch>`
3. Créer ou vérifier qu'une PR est ouverte vers `main`
4. Si la PR précédente a été mergée et qu'il reste des tâches, ouvrir immédiatement une nouvelle branche + PR

### Branches
- Toujours développer sur `claude/<feature>-<sessionid>`
- Ne jamais pusher directement sur `main`
- Une PR = une feature / un groupe cohérent de tâches

### Commits
- Messages clairs et préfixés : `feat:`, `fix:`, `docs:`, `chore:`
- Committer régulièrement (pas en bloc à la fin)

## Prochaines tâches prioritaires

Voir [ROADMAP.md](./ROADMAP.md) pour le détail complet.

1. **Collecteur nmap** — `agent/collectors/network_scan.py`
2. **Alembic migrations** — remplacer `create_all()` par migrations incrémentales
3. **Module LDAP/AD** — `server/modules/builtin/ldap/module.py`
4. **CVE scan côté agent** — intégration Grype ou NVD API
5. **Pages Networks + Topology + AuthRequests** dans le SPA React
