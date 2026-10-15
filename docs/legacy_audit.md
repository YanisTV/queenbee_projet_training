# Atelier J1-A2 — Audit de `legacy/log_watcher.py` et correspondance avec le refactoring

## Violations SOLID
| Principe | Constat dans le code legacy | Correction dans `src/queenbee` |
|---|---|---|
| **S** | `LogWatcher` lit, analyse, détecte, stocke, alerte et fait des rapports | une classe par raison de changer : règles (`domain/rules.py`), dépôt (`adapters/outbound/repositories.py`), notifieur (`adapters/outbound/notifiers.py`), orchestration (`application/services.py`) |
| **O** | `report()` : un `elif` de plus à chaque format (csv, html, json) | un format = une classe derrière un `Protocol` (Strategy), sans toucher l'existant — non écrit en J1, le rapport n'a pas de test associé |
| **L** | pas d'héritage, donc non applicable | — |
| **I** | aucune abstraction : tout passe par une seule grosse classe | petits `Protocol` d'un seul rôle : `Rule`, `IncidentRepository`, `Notifier` |
| **D** | la classe crée elle-même sa base, son client SMTP et son secret | tout est reçu par le constructeur (`DetectionService(rule, repository, notifiers)`), assemblage dans les fabriques |

## Violations de sécurité
| # | Constat | Menace | Correction |
|---|---|---|---|
| 1 | `SMTP_PASSWORD` écrit en dur et versionné | I | secret lu depuis l'environnement (`.env.example`, EX-07) ; le notifieur de prod ne le connaît pas en dur |
| 2 | `INSERT ... VALUES ('{ip}', '{user}')` : f-string, `ip` vient du log donc de l'attaquant | T | requêtes paramétrées `?` (EX-04) ; valeurs validées avant d'atteindre le dépôt |
| 3 | regex `Failed password for (.*) from (.*)` : `.*` gourmand, non ancré | D, T | regex ancrée avec classes bornées (`fullmatch`), aucune imbrication de quantificateurs (EX-02) ; parseur complet au Jour 2 |
| 4 | `open(self.path)` jamais fermé, aucune limite de taille | D | `with`, lecture bornée (J2) |
| 5 | `if self.counts[ip] == 5` : l'alerte ne se déclenche qu'au 5e échec exact, jamais ensuite | logique | `n >= seuil` dans `BruteForceRule` |
| 6 | `self.counts` croît sans limite, clé choisie par l'attaquant | D (mémoire) | comptage sur un lot d'événements validés, sans état global |
| 7 | `DB` connexion globale créée à l'import, table jamais créée, jamais de `commit()` : rien n'est persisté | I, disponibilité | dépôt injecté, schéma créé dans le constructeur, `commit()` dans `save` |
| 8 | SMTP sans TLS, identifiants envoyés en clair, corps construit par f-string | I | notifieur isolé derrière un port ; champs de l'alerte validés (IP, pas de retour à la ligne) |
| 9 | `report("html")` concatène des valeurs non échappées | XSS | échapper (`html.escape`) à tout futur rendu HTML ; pour le CSV, neutraliser les cellules qui commencent par `=`, `+`, `-`, `@` |
| 10 | `report` renvoie `None` pour un format inconnu, `str(dict)` pour « json » | T | refuser explicitement l'inconnu (comme `build_rule`), `json.dumps` |
| 11 | aucune trace de qui a fait quoi | R | journal d'audit (EX-08, J2) |
