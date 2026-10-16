# ADR 0001 — Architecture hexagonale (ports et adaptateurs)

- **Statut** : accepté — 15 octobre 2026
- **Décideurs** : équipe projet Queen Bee (décision collective ; les noms individuels n’étaient pas fournis dans les éléments remis).

## Contexte
Queen Bee reçoit des données **non fiables** de trois sources : les lignes de journaux des hôtes, les messages des agents et, plus tard, un flux de renseignement sur les menaces. Le code de départ (`legacy/log_watcher.py`) mélange lecture, analyse, détection, stockage et alerte dans une seule classe : une entrée piégée atteint directement la base (injection SQL) et un changement de base ou de mail oblige à tout réécrire. Il faut pouvoir tester la détection sans base, sans réseau et sans secret.

## Décision
Le **domaine** (entités, règles) ne dépend de rien. La couche **application** définit des **ports** (`Protocol`) ; les **adaptateurs** les implémentent ; un seul endroit (`bootstrap` et les fabriques) assemble le tout. Le sens des dépendances est imposé par un contrat `import-linter` : `bootstrap -> adapters -> application -> domain`.

## Alternatives écartées
- **Architecture en couches classique** (interface -> service -> accès aux données, le domaine important la base) : le domaine dépend alors de SQLite, donc impossible de le tester seul, et le contrôle des entrées est dispersé.
- **Script unique** (comme `legacy/`) : surface d'attaque maximale, aucune frontière où valider, tests impossibles sans vraie base ni vrai serveur de mail.
- **Microservices** : isolation forte, mais coût d'exploitation, authentification entre services et réseau à sécuriser, disproportionné pour une équipe de ce projet.

## Conséquences
+ Les données externes sont validées à l'entrée du domaine : un `SecurityEvent` ne peut pas être invalide.
+ Les cas d'usage se testent avec des doublures (mémoire), sans base ni réseau.
+ Remplacer SQLite ou le notifieur ne touche ni le domaine ni les cas d'usage.
− Plus de fichiers et d'indirections (ports, fabriques) pour un petit projet.
− Il faut de la discipline : le contrat `import-linter` doit rester dans la CI, sinon les dépendances dérivent.

## Menaces STRIDE traitées
- **T** · Intégrité : objets figés et validés à la construction (`SecurityEvent`, `Alert`, règles).
- **E** · Contrôle d'accès : un point unique, le cas d'usage, où vérifier le rôle (EX-05).
- **I** · Confidentialité : les secrets ne vivent que dans la configuration et le point d'assemblage, jamais dans le domaine (EX-07).
- **D** · Disponibilité : tailles bornées et regex sans quantificateurs imbriqués aux frontières (EX-02).

## Diagrammes associés
- Contexte C4 niveau 1 : `docs/uml/c4_context.puml`.
- Classes et cinq patterns défensifs : `docs/uml/class_patterns.puml`.
- Parcours, frontières de confiance et tranche verticale : `docs/journey_and_vertical_slice.md`.

## Preuve
- Contrat d'architecture : `PYTHONPATH=src lint-imports` (« Architecture hexagonale : les dépendances pointent vers le domaine » — KEPT).
- `tests/test_domain.py::test_invalid_event_cannot_exist`
- `tests/test_creational.py::test_service_runs_with_any_family` (le même cas d'usage tourne avec n'importe quelle famille d'adaptateurs).
