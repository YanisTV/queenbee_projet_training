# Parcours utilisateur et tranche verticale — J2

## 1. Parcours « attaque détectée → incident clos » (8 étapes)

| # | Action / résultat | Composant principal | Frontière franchie | Menace STRIDE et contrôle |
|---:|---|---|---|---|
| 1 | Un agent collecte une tentative de connexion et prépare un message | Agent (extérieur) | **TB1 : réseau agent → API** | **S/T** : usurpation ou altération ; HMAC-SHA256 et comparaison en temps constant |
| 2 | Le message est reçu, borné à 4 Kio, authentifié, décodé et validé strictement | `parse_agent_message` | TB1 | **D/T** : corps trop grand, JSON malformé ou champs supplémentaires ; rejet avant ingestion |
| 3 | Les données sont converties en `SecurityEvent` validé | `SecurityEvent` / adaptateur entrant | frontière entrée → domaine | **T** : IP, action, utilisateur et horodatage validés ; objet figé |
| 4 | La règle compte les échecs par IP et produit une alerte si le seuil est atteint | `BruteForceRule` / `DetectionService` | frontière application → domaine | **T/D** : règle et seuil validés ; traitement déterministe sur le lot reçu |
| 5 | Un incident `OPEN` est créé et sauvegardé | `DetectionService` + `IncidentRepository` | **TB2 : application → stockage** | **T/I** : valeurs validées et requêtes SQLite paramétrées ; accès stockage encapsulé derrière un port |
| 6 | L'alerte est diffusée aux abonnés, auditée et limitée en débit | `Notifier`, `AuditedNotifier`, `RateLimitedNotifier` | frontière application → notification/SIEM | **D/R/I** : limitation comptée (`dropped`), trace d'audit ; échec d'un abonné isolé et journalisé |
| 7 | L'analyste consulte les incidents ouverts | `IncidentReadProxy` / `QueenBee.open_incidents` | **TB4 : analyste → cas d'usage** | **E/I** : rôle `viewer`, `analyst` ou `admin` requis ; refus avant délégation |
| 8 | L'analyste fait passer l'incident de `OPEN` à `TRIAGED`, puis de `TRIAGED` à `CLOSED` | `IncidentService.move` + `Incident.transition_to` | TB4, puis application → stockage (TB2) | **E/T/R** : autorisation avant lecture/modification ; transitions imposées par la machine à états ; sauvegarde après validation |

Les frontières TB1, TB2 et TB4 sont des frontières de confiance distinctes. Le code livré simule les ports de pare-feu et de notification ; l'authentification web/MFA et le transport HTTPS du parcours sont des hypothèses d'intégration, pas des fonctionnalités prouvées par les tests locaux.

## 2. Tranche verticale : détection de force brute

### Règle métier et unités

Pour un lot d'événements validés, `BruteForceRule` compte les événements dont `action == login_failed`, regroupés par adresse IP source. Une alerte `brute_force` de gravité `HIGH` est créée pour chaque IP dont le nombre d'échecs est **supérieur ou égal** au seuil. L'unité du seuil est donc le **nombre d'événements dans le lot**, pas une durée : le code actuel ne calcule pas une fenêtre glissante temporelle.

Le code garantit actuellement un seuil entier strictement positif (`type(x) is int`, donc `True` est refusé). Pour éviter une configuration déraisonnable, le seuil est maintenant borné à **1–10 000 événements** dans la règle et le Builder. Cette borne supérieure est un choix opérationnel de ce rendu, à revoir si le contrat de volumétrie change.

### Contrat d'interface

- Règle : `Rule.evaluate(events: Sequence[SecurityEvent]) -> list[Alert]`.
- Cas d'usage : `DetectionService.ingest(events) -> list[Incident]`.
- Persistance : `IncidentRepository.save(incident)` via `Protocol`; le cas d'usage ne dépend ni de SQLite ni du dépôt mémoire.
- Sortie : une alerte mène à un incident `OPEN`, persisté avant la diffusion de la notification.

### Persistance et contraintes

`SqliteIncidentRepository` crée une table avec identifiant primaire et champs `NOT NULL`. Toutes les valeurs sont passées via paramètres `?` (jamais interpolées dans le SQL). `get` reconstruit `Alert` et `Incident`, qui revalident leurs invariants. Le dépôt mémoire implémente le même port pour les tests sans I/O.

### Scénario de recette

1. Préparer cinq `SecurityEvent` valides `login_failed` depuis `10.0.0.66`.
2. Exécuter `DetectionService(BruteForceRule(threshold=5), repo, [notifier]).ingest(events)`.
3. Vérifier qu'un seul incident `OPEN` est retourné et retrouvé par `repo.list_open()`.
4. Vérifier qu'une alerte est reçue avec règle `brute_force` et l'IP attendue.
5. Avec quatre échecs, vérifier qu'aucun incident n'est créé.
6. Vérifier qu'un seuil égal à 0, un booléen ou un seuil supérieur à 10 000 est refusé.
7. Avec un notifier en panne avant un notifier sain, vérifier que l'incident reste persisté, que le second notifier reçoit l'alerte et que l'échec est compté/journalisé.

Tests de référence : `tests/test_services.py::test_detection_creates_incident_and_notifies`, `tests/test_j2_complements.py::test_observer_failing_subscriber_does_not_block_others`, et les tests de validation du seuil dans `tests/test_j2_complements.py`.

## 3. Comparaison d'architectures

| Critère | Hexagonale (choisie) | Microservices (écartée pour ce périmètre) |
|---|---|---|
| Maintenabilité | Ports stables, domaine isolé, adaptateurs remplaçables ; discipline de couches nécessaire | Déploiements indépendants mais contrats distribués et diagnostic interservices plus complexes |
| Frontières réseau | Peu de frontières à l'intérieur du service ; frontières externes explicites | Davantage de frontières réseau entre services, à authentifier et surveiller |
| Secrets | Clé HMAC et secrets d'intégration centralisés à l'assemblage | Secrets potentiellement multiples (service-à-service, stockage, bus, etc.) |
| Failles typiques | Mauvais contrôle à un port, dépendances inversées, mauvaise validation d'adaptateur | En plus : usurpation de service, erreurs de configuration réseau, fuite via bus et appels distribués |
| Proportionnalité | Adaptée à une petite équipe, un délai court et une volumétrie de formation ; tests rapides sans réseau | Surcoût d'exploitation et de sécurité non justifié par le périmètre actuel |

## 4. Points hors périmètre / risques résiduels

- Un agent compromis qui détient une clé valide peut signer de faux événements ; une clé par agent et une révocation seraient nécessaires pour réduire ce risque.
- L'audit local est journalisé mais n'est pas garanti non effaçable.
- Le code ne met pas en œuvre une UI web/MFA, un transport HTTPS, un SIEM réel ou un pare-feu système réel : ce sont des interfaces/intégrations à fournir hors de ce projet de formation.
