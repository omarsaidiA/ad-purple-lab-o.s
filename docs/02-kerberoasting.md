# Scénario 2 : Kerberoasting

| | |
|---|---|
| **MITRE ATT&CK** | T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) |
| **Prérequis attaquant** | Un compte de domaine quelconque (ici `LAB\alice`) |
| **Outils** | [Impacket](https://github.com/fortra/impacket) (`GetUserSPNs.py`), outil de cassage hors ligne |
| **Faiblesse du lab** | `svc_sql` : SPN, mot de passe faible, membre d'un groupe privilégié |
| **Snapshot de départ** | `02-vulnerable` |

## 1. Principe

N'importe quel utilisateur du domaine peut demander au DC un **ticket de service
(TGS)** pour tout compte qui porte un SPN. Une partie de ce ticket est chiffrée
avec une clé dérivée du **mot de passe du compte de service**. L'attaquant
récupère le ticket et tente de casser cette partie **hors ligne**, sans plus
interagir avec le domaine.

Le risque dépend de deux facteurs :

- **le mot de passe** : un compte de service avec un mot de passe humain et
  rarement changé est la cible idéale ;
- **le chiffrement** : avec RC4 (type `0x17`), le calcul est bien plus rapide
  qu'avec AES. Les outils demandent donc RC4 en priorité si le compte l'accepte.

## 2. Observation dans le lab

Depuis Kali, avec le compte `alice`, je liste les comptes qui ont un SPN, puis je
demande leur TGS avec `GetUserSPNs.py` (voir la documentation d'Impacket). Je
tente ensuite le cassage hors ligne avec une petite liste de mots, pour démontrer
la faiblesse du mot de passe, sans chercher la performance.

TODO (captures) : liste des comptes avec SPN renvoyée par l'outil, **hash
tronqué** (jamais le hash complet dans le dépôt).

TODO (observation) : type de chiffrement obtenu (RC4 ou AES), temps de cassage,
et ce qui change si `msDS-SupportedEncryptionTypes` du compte est réglé sur AES.

## 3. Trace laissée dans les journaux

| Source | Événement | Champs utiles |
|---|---|---|
| Security (DC) | **4769** : un ticket de service Kerberos a été demandé | `ServiceName`, `TicketEncryptionType`, `IpAddress`, `TargetUserName` (demandeur), `TicketOptions` |

Ce qui distingue l'attaque de l'usage normal :

- `TicketEncryptionType = 0x17` (RC4) alors que le domaine négocie normalement de
  l'AES (`0x12`) ;
- `ServiceName` est un **compte utilisateur** (pas un compte machine terminé par
  `$`, ni `krbtgt`) ;
- **plusieurs services différents** demandés en quelques secondes depuis la même
  adresse IP.

TODO (captures) : événement 4769 brut correspondant à mon test (Observateur
d'événements ou alerte Wazuh).

Prérequis d'audit : « Audit Kerberos Service Ticket Operations » activé en
succès sur les DC (voir [detections/README.md](../detections/README.md)).

## 4. Règle de détection

- `100110` : un 4769 en RC4 pour un compte de service utilisateur (niveau 8).
- `100111` : au moins 3 événements `100110` depuis la même IP en 60 secondes
  (niveau 12, rafale typique d'un Kerberoasting).
- Leurre : le compte `svc_legacy` du scénario 1 porte un SPN factice. **Tout**
  ticket demandé pour lui est suspect (`100112`, niveau 12, quasiment sans faux
  positif).

Fichier : [local_rules.xml](../detections/wazuh/local_rules.xml). Analyse hors
ligne équivalente :

```bash
python scripts/ad_triage.py logs exports/alerts.json --kerberoast-threshold 3
```

TODO (test) : vrai positif sur l'attaque, puis faux positifs observés (une
application ancienne qui demande encore du RC4 peut déclencher `100110`).

## 5. Correction / durcissement

Par ordre d'efficacité :

1. **Remplacer les comptes de service par des gMSA** (Group Managed Service
   Accounts) : mot de passe de 120 caractères, changé automatiquement, donc
   incassable en pratique.
2. À défaut, **mot de passe long et aléatoire** (25 caractères ou plus) pour
   tout compte qui garde un SPN.
3. **Forcer AES** : `msDS-SupportedEncryptionTypes = 0x18` (AES128 + AES256) sur
   les comptes de service, puis désactiver RC4 au niveau du domaine une fois les
   dépendances inventoriées.
4. **Sortir les comptes de service des groupes privilégiés** (moindre privilège).
5. Supprimer les SPN inutiles (`setspn -L` pour l'inventaire).

TODO (vérification) : après correction, le même test renvoie un ticket AES (ou
plus de ticket), le cassage échoue, et ce qu'il reste dans les journaux.

## Références

- Microsoft, documentation des Group Managed Service Accounts.
- ANSSI, point de contrôle « Comptes de service avec SPN et mot de passe faible »
  (référentiel ADS).
