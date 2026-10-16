# Modèle de menaces — Queen Bee

## 1. Actifs
| Actif | Pourquoi il compte | C / I / D |
|---|---|---|
| Incidents | preuve + pilotage de la réponse | C, I |
| Clé HMAC agents | permet d'injecter de faux événements | C |
| Règles de détection | un attaquant qui les modifie devient invisible | I |
| Journal d'audit | prouve qui a fait quoi, et quand | I |
| Disponibilité de l'ingestion | si elle tombe, le SOC est aveugle | D |

## 2. Acteurs
Agent (machine), Analyste SOC, Admin, Attaquant externe, Agent compromis.

## 3. Frontières de confiance
TB1 Réseau agents -> API ingestion · TB2 Application -> base · TB3 Application -> pare-feu · TB4 Analyste -> cas d’usage · TB5 Détection -> abonnés de notification / SIEM

## 4. STRIDE par flux
| Flux | S | T | R | I | D | E | Exigence |
|---|---|---|---|---|---|---|---|
| F1 Agent -> Ingestion (TB1) | faux agent | message altéré, champ en trop | | | flood, ligne piégée (ReDoS) | | EX-01, EX-02, EX-03 |
| F2 Application -> Base (TB2) | | injection SQL via IP / nom d'utilisateur | | | | | EX-04 |
| F3 Application -> Pare-feu (TB3) | | commande forgée (`10.0.0.1; iptables -F`) | | | | | EX-04 |
| F4 Analyste -> Cas d'usage (TB4) | | | action niée | | | un viewer clôt un incident | EX-05, EX-08 |
| F5 Détection -> Notification analyste | | | alerte sans trace | secret dans les logs | tempête d'alertes | | EX-06, EX-07, EX-08 |
| F6 Agent/API -> Domaine (après authentification) | champ falsifié | événement modifié ou hors schéma | | données sensibles | corps trop grand / JSON imbriqué | élévation via champ `is_admin` | EX-01, EX-02, EX-03, EX-05 |
| F7 Détection -> N abonnés (TB5) | | alerte modifiée | échec de diffusion non tracé | détail exposé dans les logs | abonné lent ou en panne | | EX-06, EX-08 ; échec isolé et journalisé |

## 5. Exigences de sécurité (EX-nn, testables)

Le test de qualité d'une exigence : peut-on écrire le test qui échoue si elle est violée ?
La colonne « État » dit si le test passe aujourd'hui (J1) ou si le code correspondant est attendu en J2/J3.

- **EX-01** Tout message d'agent est authentifié (HMAC-SHA256, comparaison en temps constant).
  Menace : S sur TB1 · Propriété : Authenticité.
  Test : `tests/test_adapters.py::test_abuse_forged_signature_rejected` — État : **vert (J2)**.
- **EX-02** Toute ligne de journal piégée DOIT être rejetée, et 1 000 lignes piégées DOIVENT être traitées en moins de 1 s.
  Menace : D sur TB1 · Propriété : Disponibilité.
  Tests : `test_parser_is_fast_on_adversarial_input`, `test_malicious_lines_rejected` (`tests/test_adapters.py`) — État : **vert (J2)**.
- **EX-03** Un événement invalide ne peut pas exister (IP, nom d'utilisateur, action hors liste blanche, horodatage sans fuseau), un message avec un champ en trop est refusé, et un incident ne peut pas sauter l'étape de triage.
  Menace : T sur TB1 · Propriété : Intégrité.
  Tests : `tests/test_domain.py::test_invalid_event_cannot_exist`, `test_naive_timestamp_rejected`, `test_event_is_immutable`, `test_state_forbids_skipping_triage` — État : **vert (J1)** ; `tests/test_adapters.py::test_abuse_extra_field_rejected` — **vert (J2)**.
- **EX-04** Aucune donnée externe n'est interprétée comme du SQL ni comme une commande : requêtes paramétrées, commandes construites uniquement après validation de l'IP.
  Menace : T sur TB2 et TB3 · Propriété : Intégrité.
  Tests : `tests/test_services.py::test_sqlite_repo_resists_injection`, `test_command_undo`, `tests/test_j2_complements.py::test_abuse_forged_ip_never_reaches_the_firewall` — État : **vert (J2)**.
- **EX-05** Le rôle de l'appelant est vérifié dans le cas d'usage, jamais seulement dans l'interface.
  Menace : E sur TB4 · Propriété : Contrôle d'accès (autorisation).
  Tests : `tests/test_services.py::test_abuse_viewer_cannot_close_incident`, `test_proxy_blocks_principal_without_role`, `tests/test_j2_complements.py::test_abuse_guest_cannot_read_incidents`, `test_abuse_viewer_cannot_write_through_the_proxy` — État : **vert (J2)**.
- **EX-06** Une tempête de 1 000 alertes n'en transmet qu'un nombre borné par fenêtre de temps (limite de débit).
  Menace : D sur F5 · Propriété : Disponibilité.
  Test : `tests/test_services.py::test_abuse_rate_limiter_absorbs_alert_flood` — État : **vert (J2)**.
- **EX-07** Un secret n'apparaît jamais dans `repr()`, `print()` ni les journaux, et l'application refuse de démarrer sans clé valide (32 octets minimum).
  Menace : I · Propriété : Confidentialité.
  Tests : `tests/test_adapters.py::test_secret_never_printed`, `test_missing_secret_refuses_to_start` — État : **vert (J2)**.
- **EX-08** Toute alerte notifiée laisse une trace d'audit horodatée contenant le nom de la règle.
  Menace : R sur F4/F5 · Propriété : Preuve.
  Test : `tests/test_services.py::test_audit_decorator_logs` — État : **vert (J2)**.

## 6. Flux mis à jour après le parcours J2

- Le flux F6 rend explicite la validation stricte entre la frontière réseau TB1 et le domaine : aucune propriété de rôle fournie par l’agent n’est acceptée comme autorisation.
- Le flux F7 distingue la diffusion multi-abonnés de la détection elle-même. Une panne de notifier est comptée dans `DetectionService.notification_failures`, journalisée et n’empêche pas les abonnés suivants de recevoir l’alerte. La limitation de débit conserve son compteur `dropped`.
- La tranche verticale de détection est décrite dans `docs/journey_and_vertical_slice.md`; les cinq patterns sont illustrés dans `docs/uml/class_patterns.puml`.

## 7. Risques résiduels (acceptés, à surveiller)
- **Agent compromis** : il possède légitimement la clé HMAC et peut signer de faux événements. EX-02 et EX-03 limitent les dégâts (format borné, valeurs validées) mais ne l'empêchent pas : il faudrait une clé par agent et une révocation.
- **Journal d'audit** : EX-08 garantit la trace, pas son caractère non effaçable. Cela demande un stockage en écriture seule, hors périmètre de ce projet.
