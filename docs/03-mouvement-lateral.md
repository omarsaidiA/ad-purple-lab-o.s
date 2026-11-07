# Scénario 3 : mouvement latéral

| | |
|---|---|
| **MITRE ATT&CK** | T1021.002 (SMB / Admin Shares), T1569.002 (Service Execution), T1047 (WMI), T1550.002 (Pass the Hash) |
| **Prérequis attaquant** | L'empreinte NTLM ou le mot de passe du compte `localadmin` d'une machine |
| **Outils** | [Impacket](https://github.com/fortra/impacket) (`psexec.py`, `wmiexec.py`), [NetExec](https://github.com/Pennyw0rth/NetExec) |
| **Faiblesse du lab** | Même mot de passe administrateur local sur SRV01 et CLIENT01, pas de LAPS |
| **Snapshot de départ** | `02-vulnerable` |

## 1. Principe

Une fois administrateur d'une machine, l'attaquant cherche à **rebondir** sur
d'autres. Deux erreurs de configuration rendent cela facile :

- **mot de passe administrateur local identique** partout : l'empreinte NTLM
  récupérée sur une machine ouvre toutes les autres (pass-the-hash, sans casser
  le mot de passe) ;
- **exécution à distance ouverte** : SMB (partage `ADMIN$` et création de
  service) ou WMI, accessibles depuis n'importe quel poste.

Deux méthodes d'exécution différentes laissent des traces différentes :

- **type PsExec** : copie d'un binaire sur `ADMIN$`, puis création et démarrage
  d'un service ;
- **type WMIExec** : `Win32_Process.Create` via WMI ; le processus est lancé par
  `WmiPrvSE.exe`, et la sortie passe par un fichier sur `ADMIN$`.

## 2. Observation dans le lab

Depuis Kali, avec l'empreinte du compte `localadmin` (obtenue au cours du lab),
je teste l'accès aux machines avec NetExec, puis j'exécute une commande anodine
(`whoami`, `hostname`) avec chacune des deux méthodes. Pour la syntaxe, je suis la
documentation d'Impacket et de NetExec.

TODO (captures) : machines sur lesquelles l'empreinte est acceptée (« Pwn3d! »
dans NetExec), sortie des commandes anodines.

TODO (observation) : ce que Microsoft Defender a bloqué ou signalé (si activé),
et différence de bruit entre psexec et wmiexec.

## 3. Trace laissée dans les journaux

| Source | Événement | Ce qu'on y voit |
|---|---|---|
| Security (cible) | **4624**, type 3, `AuthenticationPackageName = NTLM` | Connexion réseau avec le compte local, depuis l'IP de Kali |
| Security (cible) | **4672** | Privilèges spéciaux attribués à la session (compte administrateur) |
| Security (cible) | **5145** | Accès au partage `ADMIN$` / `IPC$` (audit « Detailed File Share ») |
| System (cible) | **7045** | Service installé : nom aléatoire, binaire dans `%SystemRoot%` (type PsExec) |
| Sysmon (cible) | **1** | `cmd.exe` lancé par `WmiPrvSE.exe`, ligne de commande avec `\\127.0.0.1\ADMIN$\__<horodatage>` (type WMIExec) |
| Sysmon (cible) | **11** | Fichier créé dans `C:\Windows\` par `System` (binaire déposé via SMB) |

Signal le plus robuste : **le même compte local s'authentifie en NTLM sur
plusieurs machines en peu de temps, depuis la même source**. Un administrateur
légitime utilise son compte de domaine en Kerberos, pas un compte local en NTLM.

TODO (captures) : 7045 et Sysmon 1 correspondant à mes tests.

## 4. Règle de détection

- `92650` (règle **native** de Wazuh) : service installé (7045) dont le binaire
  est à la racine de `%SystemRoot%`, le schéma de PsExec et d'Impacket (niveau 12).
- `100130` : complément, service lancé depuis un dossier temporaire (niveau 10).
- `100131` : processus lancé par `WmiPrvSE.exe` avec une redirection vers
  `\\127.0.0.1\ADMIN$\__` : signature de wmiexec (niveau 12). Elle est déclarée
  comme fille de la règle native `92069` (« WMI a lancé un processus », niveau 0),
  sinon celle-ci la masque.
- `100132` / `100133` : connexion NTLM réseau avec un compte non-machine, puis le
  même compte sur 3 événements en 2 minutes (niveau 10).

Fichier : [local_rules.xml](../detections/wazuh/local_rules.xml). Analyse hors
ligne : `python scripts/ad_triage.py logs exports/alerts.json --lateral-threshold 3`.

TODO (test) : vrai positif pour chaque méthode, faux positifs (déploiement
logiciel, outils d'administration qui installent un service).

## 5. Correction / durcissement

1. **Windows LAPS** : un mot de passe administrateur local unique et changé
   automatiquement sur chaque machine, stocké dans l'AD avec un accès restreint.
   L'empreinte d'une machine n'ouvre plus les autres.
2. **Interdire la connexion réseau des comptes locaux** : GPO « Interdire
   l'accès à cet ordinateur à partir du réseau » pour le groupe `Compte local et
   membre du groupe Administrateurs` (SID S-1-5-114).
3. **Pare-feu Windows** : SMB (445) et WMI / RPC (135, ports dynamiques)
   accessibles uniquement depuis les postes d'administration.
4. **Modèle en tiers** : les comptes d'administration des serveurs ne se
   connectent jamais aux postes utilisateurs, et inversement.
5. **Signature SMB obligatoire** : complète la protection contre le relais NTLM.

TODO (vérification) : après LAPS et la GPO, la même empreinte est refusée sur
les autres machines. Capture de l'échec et des 4625 correspondants.

## Références

- Microsoft, documentation de Windows LAPS.
- ANSSI, « Recommandations relatives à l'administration sécurisée des SI ».
