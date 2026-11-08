# Scénario 3 : mouvement latéral

| | |
|---|---|
| **MITRE ATT&CK** | T1021.002 (SMB / Admin Shares), T1569.002 (Service Execution), T1047 (WMI), T1550.002 (Pass the Hash) |
| **Prérequis attaquant** | L'empreinte NTLM ou le mot de passe du compte `localadmin` d'une machine |
| **Outils** | [Impacket](https://github.com/fortra/impacket) (`psexec.py`, `wmiexec.py`), [NetExec](https://github.com/Pennyw0rth/NetExec) |
| **Faiblesse du lab** | Même mot de passe administrateur local sur SRV01 et CLIENT01, pas de LAPS |
| **Règles** | 92650 (native), 100130, 100131, 100132, 100133 |
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

## 2. Reproduction et résultat attendu

**Procédure.** Depuis Kali, avec l'empreinte du compte `localadmin`, tester
l'accès aux machines avec NetExec, puis exécuter une commande anodine (`whoami`,
`hostname`) avec chacune des deux méthodes, en suivant la documentation
d'Impacket et de NetExec.

**Résultat attendu :**

- NetExec indique un accès administrateur (`Pwn3d!`) sur SRV01 **et** CLIENT01
  avec la même empreinte : c'est la conséquence directe de l'absence de LAPS ;
- `psexec.py` crée un service au nom aléatoire dont le binaire est déposé à la
  racine de `%SystemRoot%` ;
- `wmiexec.py` ne crée pas de service : la commande est lancée par
  `WmiPrvSE.exe`. Elle laisse donc moins de traces dans les journaux par défaut,
  d'où l'intérêt de Sysmon ;
- si Microsoft Defender est actif, le binaire de service de `psexec.py` est
  souvent bloqué, alors que `wmiexec.py` passe plus facilement. C'est un point de
  comparaison utile entre la prévention et la détection.

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

**Alertes produites par Wazuh 4.14** dans le banc de test :

```json
{
  "rule": { "id": "100131", "level": 12,
            "description": "AD lab: remote command through WMI on CLIENT01.lab.internal (wmiexec pattern)" },
  "data": { "win": {
    "system": { "eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational" },
    "eventdata": {
      "parentImage": "C:\\\\Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe",
      "image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
      "commandLine": "cmd.exe /Q /c whoami 1&gt; \\\\\\\\127.0.0.1\\\\ADMIN$\\\\__1762596060.12 2&gt;&amp;1" } } }
}
```

```json
{
  "rule": { "id": "92650", "level": 12,
            "description": "New Windows Service Created to start from windows root path. Suspicious event as the binary may have been dropped using Windows Admin Shares." },
  "data": { "win": {
    "system": { "eventID": "7045", "channel": "System", "computer": "SRV01.lab.internal" },
    "eventdata": { "serviceName": "BTOBTO", "imagePath": "%systemroot%\\\\aBcDeFgH.exe",
                   "accountName": "LocalSystem" } } }
}
```

Dans ces extraits, les antislashs sont doublés : c'est ainsi que Wazuh stocke les
champs Windows (voir [detections/README.md](../detections/README.md#4-centralisation-dans-wazuh)).
Les règles et le script d'analyse en tiennent compte.

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
ligne : `python scripts/ad_triage.py logs exports/archives.json --lateral-threshold 3`.

**Validation** (banc de test, Wazuh 4.14.5) :

| Cas | Attendu | Résultat |
|---|---|---|
| 7045, binaire `%systemroot%\aBcDeFgH.exe` | 92650 (native) | ✅ |
| 7045, binaire `C:\Windows\Temp\updsvc.exe` | 100130 | ✅ |
| 7045, installation légitime de `C:\Windows\Sysmon64.exe` | aucune règle du lab | ✅ |
| Sysmon 1, `cmd.exe` lancé par `WmiPrvSE.exe` vers `ADMIN$\__` | 100131 | ✅ |
| `localadmin` en NTLM sur DC01, SRV01, CLIENT01 | 100132, 100132, 100133 | ✅ |
| Compte machine `CLIENT01$` en NTLM | aucune règle du lab | ✅ |

**Faux positifs connus :** les outils de déploiement logiciel installent eux
aussi des services. On les identifie au chemin du binaire et au compte source,
puis on les ajoute en exception **nominative**.

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

**Contrôle après correction (résultat attendu).** Avec LAPS, l'ancienne
empreinte est refusée partout ; avec la GPO S-1-5-114, même le bon mot de passe
local est refusé à distance. Les tentatives laissent des **4625** (échec
d'ouverture de session) sur les cibles : un signal à surveiller à son tour.

## Références

- Microsoft, documentation de Windows LAPS.
- ANSSI, « Recommandations relatives à l'administration sécurisée des SI ».
