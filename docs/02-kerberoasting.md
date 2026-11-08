# Scénario 2 : Kerberoasting

| | |
|---|---|
| **MITRE ATT&CK** | T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) |
| **Prérequis attaquant** | Un compte de domaine quelconque (ici `LAB\alice`) |
| **Outils** | [Impacket](https://github.com/fortra/impacket) (`GetUserSPNs.py`), outil de cassage hors ligne |
| **Faiblesse du lab** | `svc_sql` : SPN, mot de passe faible, membre d'un groupe privilégié |
| **Règles** | 100110, 100111, 100112 |
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

## 2. Reproduction et résultat attendu

**Procédure.** Depuis Kali, avec le compte `alice`, lister les comptes qui ont
un SPN puis demander leur TGS avec `GetUserSPNs.py` (voir la documentation
d'Impacket). Le cassage hors ligne se fait avec une petite liste de mots : le but
est de démontrer la faiblesse du mot de passe, pas la performance.

**Résultat attendu :**

- `svc_sql` (et le leurre `svc_legacy`) apparaissent dans la liste des comptes
  avec SPN ;
- tant que le compte n'a pas `msDS-SupportedEncryptionTypes` réglé sur AES, le
  ticket revient en **RC4 (`0x17`)**. Le mot de passe faible de `svc_sql` est
  retrouvé en quelques secondes avec une liste de mots courante ;
- sur un DC récent qui restreint RC4 par défaut, le ticket peut revenir en AES
  (`0x12`). Le Kerberoasting reste alors possible, mais le cassage est beaucoup
  plus lent : c'est déjà l'effet du durcissement du §5.

Règle de publication : les tickets et empreintes ne sont jamais mis en entier
dans le dépôt (voir [captures/README.md](captures/README.md)).

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

Prérequis d'audit : « Audit Kerberos Service Ticket Operations » activé en
succès sur les DC (voir [detections/README.md](../detections/README.md)).

**Alerte produite par Wazuh 4.14** dans le banc de test, au troisième ticket RC4
venu de la même IP :

```json
{
  "rule": { "id": "100111", "level": 12,
            "description": "AD lab: burst of RC4 service tickets from ::ffff:10.10.10.50 (possible Kerberoasting)" },
  "data": { "win": {
    "system": { "eventID": "4769", "channel": "Security", "computer": "DC01.lab.internal" },
    "eventdata": { "targetUserName": "alice@LAB.INTERNAL", "serviceName": "svc_backup",
                   "ticketEncryptionType": "0x17", "ipAddress": "::ffff:10.10.10.50" } } }
}
```

Le DC enregistre les clients IPv4 sous forme d'adresse IPv6 « mappée »
(`::ffff:10.10.10.50`). Le script d'analyse retire ce préfixe avant de regrouper.

## 4. Règle de détection

- `100110` : un 4769 en RC4 (`0x17` ou `0x18`) pour un compte de service
  utilisateur (niveau 8).
- `100111` : 3 événements `100110` depuis la même IP en 60 secondes (niveau 12,
  rafale typique d'un Kerberoasting).
- `100112` : **tout** ticket demandé pour le leurre `svc_legacy`, quel que soit
  le chiffrement (niveau 12, quasiment sans faux positif).

Fichier : [local_rules.xml](../detections/wazuh/local_rules.xml). Analyse hors
ligne équivalente :

```bash
python scripts/ad_triage.py logs exports/archives.json --kerberoast-threshold 3
```

**Validation** (banc de test, Wazuh 4.14.5) :

| Cas | Attendu | Résultat |
|---|---|---|
| 3 tickets RC4 pour `svc_sql`, `svc_web`, `svc_backup` depuis 10.10.10.50 | 100110, 100110, 100111 | ✅ |
| Ticket RC4 pour le compte machine `SRV01$` | aucune règle du lab | ✅ |
| Ticket AES pour `svc_web` | aucune règle du lab | ✅ |
| Ticket AES pour le leurre `svc_legacy` | 100112 | ✅ |

**Faux positif connu :** une application ancienne qui ne parle que RC4 déclenche
`100110` à chaque ticket. On l'identifie à son IP et à son service, puis on la
corrige (passage en AES) plutôt que de l'exclure de la règle.

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

**Contrôle après correction (résultat attendu).** Le même test renvoie un ticket
AES (`0x12`), ce qui ne déclenche plus `100110`. Avec un gMSA, le cassage n'est
plus réaliste. Le 4769 reste journalisé : la règle du leurre `100112` continue de
couvrir la phase de demande.

## Références

- Microsoft, documentation des Group Managed Service Accounts.
- ANSSI, point de contrôle « Comptes de service avec SPN et mot de passe faible »
  (référentiel ADS).
