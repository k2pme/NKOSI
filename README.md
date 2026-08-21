CAHIER DES CHARGES ET SPÉCIFICATIONS FONCTIONNELLES
ANTIVIRUS / ENDPOINT SECURITY LINUX — V1

Version : 1.0
Cible initiale : Debian / Ubuntu — x86-64
Nature du produit : Antivirus et protection endpoint locale
Statut : Spécification de référence V1

1. OBJET DU DOCUMENT

Le présent document définit le cahier des charges et les spécifications fonctionnelles de la version 1 d’une application antivirus / endpoint security destinée aux postes Linux Debian et Ubuntu.

La V1 doit protéger localement une machine Linux contre des fichiers malveillants, des processus suspects et des connexions réseau liées à des indicateurs de compromission connus. Elle doit corréler plusieurs signaux de détection, calculer un score de risque, déclencher une réponse proportionnée et conserver les éléments permettant d’expliquer la décision.

Le produit doit fonctionner sans dépendance permanente à un service cloud. Les données de Threat Intelligence sont synchronisées périodiquement puis exploitées localement.

2. OBJECTIFS DE LA V1

La V1 doit permettre de :
• surveiller en temps réel les créations et modifications de fichiers ;
• lancer un scan manuel d’un fichier, dossier ou système ;
• calculer les empreintes cryptographiques des fichiers, notamment SHA-256 ;
• comparer ces empreintes à une base locale de menaces ;
• appliquer des règles YARA ;
• réaliser une analyse statique basique des fichiers exécutables et scripts ;
• surveiller les processus et leurs comportements ;
• surveiller les connexions réseau associées aux processus ;
• corréler les événements de sécurité ;
• calculer un score de risque global ;
• autoriser, alerter, bloquer, tuer un processus ou mettre un fichier en quarantaine selon la décision ;
• journaliser les événements et incidents ;
• mettre à jour la base locale de Threat Intelligence ;
• afficher l’état de protection dans une interface locale.

3. PÉRIMÈTRE TECHNIQUE

3.1 Cibles supportées
• Linux Debian, version stable supportée au moment de la livraison ;
• Ubuntu LTS ;
• architecture x86-64.

3.2 Principes d’architecture
Le produit doit être conçu en composants séparés :
• Security Agent ;
• Filesystem Monitor ;
• Process Monitor ;
• Network Monitor ;
• Event Engine ;
• Hash Engine ;
• YARA Engine ;
• Static Analyzer ;
• Behavior Engine ;
• Threat Intelligence Service ;
• Risk Engine ;
• Response Engine ;
• Event Logger ;
• Local Database ;
• Update Service ;
• Desktop UI / CLI.

3.3 Technologies recommandées
Le cœur de l’agent est recommandé en Rust. La surveillance système pourra exploiter les interfaces Linux adaptées telles que fanotify/inotify pour le système de fichiers, procfs et mécanismes système pour les processus, et des mécanismes réseau Linux adaptés pour l’observation et le blocage. YARA est utilisé pour les règles de détection statique.

4. HORS PÉRIMÈTRE DE LA V1

Ne font pas partie de la V1 :
• Windows ;
• Android ;
• macOS ;
• iOS ;
• console cloud centralisée ;
• gestion multi-endpoints ;
• SIEM ;
• EDR centralisé complet ;
• sandbox dynamique automatisée ;
• exécution automatique de malware en VM ;
• analyse mémoire avancée ;
• kernel driver personnalisé ;
• moteur IA complexe ;
• remédiation automatique avancée ;
• orchestration SOC ;
• analyse massive distribuée.

5. ARCHITECTURE FONCTIONNELLE GLOBALE

                         LINUX
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ↓                   ↓                   ↓
 Filesystem            Processes            Network
 Monitor                Monitor              Monitor
       │                   │                   │
       └────────────┬──────┴────────────┬──────┘
                    │                   │
                    ↓                   ↓
               EVENT ENGINE      Threat Intelligence
                    │                   │
        ┌───────────┼────────────┐      │
        ↓           ↓            ↓      │
      Hash        YARA         Static   │
      Engine      Engine       Analyzer │
        │           │            │      │
        └───────────┼────────────┴──────┘
                    ↓
             Behavior Engine
                    │
                    ↓
              ┌───────────┐
              │RISK ENGINE│
              └─────┬─────┘
                    │
             ┌──────┼──────┐
             ↓      ↓      ↓
           CLEAN  SUSPECT MALWARE
             │      │      │
           Allow   Alert   │
                           ↓
                    RESPONSE ENGINE
                     │     │     │
                     ↓     ↓     ↓
                   Kill  Block Quarantine
                     │     │     │
                     └─────┼─────┘
                           ↓
                       EVENT LOG
                           │
                           ↓
                      LOCAL DATABASE
                           │
                           ↓
                      DESKTOP UI

6. SPÉCIFICATIONS FONCTIONNELLES

SF-001 — Démarrage et initialisation de l’agent
L’agent de sécurité doit pouvoir démarrer automatiquement avec le système. Il charge la configuration locale, la base Threat Intelligence, les règles YARA et initialise les moniteurs.

Critères fonctionnels :
• le statut de l’agent est disponible ;
• un échec de chargement d’un composant est journalisé ;
• un composant critique indisponible place le produit dans un état « protection dégradée » ;
• la surveillance démarre sans intervention utilisateur lorsque la configuration est valide.

Diagramme d’activité :

┌──────────────┐
│ Démarrage OS │
└──────┬───────┘
       ↓
┌──────────────────────┐
│ Démarrer Security    │
│ Agent                │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Charger configuration│
│ + Threat DB + YARA   │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Activer surveillance │
│ fichiers/process/net │
└──────────┬───────────┘
           ↓
      ┌─────────────┐
      │ Événement ? │◄─────────────────┐
      └──────┬──────┘                  │
             │ Oui                     │
             ↓                         │
┌────────────────────────┐             │
│ Envoyer événement au   │             │
│ Detection Engine       │             │
└────────────┬───────────┘             │
             ↓                         │
┌────────────────────────┐             │
│ Calculer niveau risque │             │
└────────────┬───────────┘             │
             ↓                         │
       ┌───────────┐                   │
       │ Menace ?  │                   │
       └─────┬─────┘                   │
        Non  │  Oui                    │
        ┌────┴──────┐                  │
        ↓           ↓                  │
   Journaliser   Response Engine       │
        │           │                  │
        │           ↓                  │
        │      Alerte/Blocage          │
        │      /Quarantaine            │
        │           │                  │
        └───────────┴──────────────────┘

SF-002 — Surveillance temps réel du système de fichiers
Le système doit détecter les créations, modifications et événements pertinents sur les fichiers dans les zones surveillées.

Données minimales collectées :
• chemin ;
• nom ;
• taille ;
• type MIME ou type détecté ;
• propriétaire ;
• permissions ;
• horodatage ;
• origine de l’événement lorsqu’elle est disponible.

Diagramme d’activité :

Utilisateur / application
         │
         ↓
 Création/modification
      d'un fichier
         │
         ↓
┌───────────────────────┐
│ Filesystem Monitor    │
│ fanotify / inotify    │
└──────────┬────────────┘
           ↓
┌───────────────────────┐
│ Récupérer métadonnées │
│ chemin, taille, type  │
│ propriétaire...       │
└──────────┬────────────┘
           ↓
┌───────────────────────┐
│ Calcul SHA-256        │
└──────────┬────────────┘
           ↓
    ┌───────────────┐
    │ Hash dans DB ?│
    └───────┬───────┘
         Oui│     Non
            │      │
            ↓      ↓
       MALWARE   Scan YARA
            │      │
            │      ↓
            │   Match ?
            │   /     \
            │ Oui     Non
            │  │       │
            │  ↓       ↓
            │ Suspect Analyse
            │         statique
            │           │
            └─────┬─────┘
                  ↓
           Risk Scoring
                  │
                  ↓
          ┌──────────────┐
          │ Score risque │
          └───────┬──────┘
                  ↓
        ┌─────────┼─────────┐
        ↓         ↓         ↓
      FAIBLE    MOYEN     ÉLEVÉ
        │         │         │
      Allow     Alert   Quarantaine

SF-003 — Détection par empreinte SHA-256
Chaque fichier pertinent doit pouvoir être identifié par SHA-256. La comparaison doit être effectuée avec une base locale de Threat Intelligence afin d’éviter une dépendance réseau par fichier.

Diagramme d’activité :

Fichier
   │
   ↓
Calcul SHA-256
   │
   ↓
Threat Intelligence DB locale
   │
   ↓
┌───────────────────────────┐
│ SHA-256 connu ?           │
└─────────────┬─────────────┘
         Non  │  Oui
       ┌──────┴──────┐
       ↓             ↓
Continuer        Récupérer
analyse          informations
                 │
                 ├─ famille malware
                 ├─ source
                 ├─ first_seen
                 ├─ tags
                 └─ confidence
                     │
                     ↓
               Menace confirmée
                     │
                     ↓
                Quarantaine

SF-004 — Analyse YARA
Le moteur doit appliquer un ensemble local de règles YARA aux fichiers éligibles. Une correspondance YARA constitue un signal de risque et non obligatoirement une décision finale unique.

Diagramme d’activité :

Fichier inconnu
      │
      ↓
┌────────────────┐
│ YARA Engine    │
└───────┬────────┘
        ↓
Appliquer règles
        │
        ↓
 ┌─────────────┐
 │ Match YARA ?│
 └──────┬──────┘
    Non │ Oui
     │  │
     │  ↓
     │ Récupérer règle
     │  │
     │  ├─ famille
     │  ├─ sévérité
     │  ├─ catégorie
     │  └─ confidence
     │
     ↓
 Risk Scoring

SF-005 — Analyse statique basique
Le système doit analyser les caractéristiques statiques des fichiers inconnus ou suspects sans les exécuter.

Pour les exécutables et scripts, l’analyse pourra inclure :
• type de fichier ;
• permissions inhabituelles ;
• SUID/SGID ;
• chaînes de caractères ;
• URL et adresses IP embarquées ;
• commandes shell ;
• imports et bibliothèques ;
• sections de binaire ;
• anomalies structurelles ;
• indicateurs associés à l’obfuscation lorsque détectables.

Diagramme d’activité :

        Fichier
           │
           ↓
   Identifier type
           │
     ┌─────┼─────┐
     ↓     ↓     ↓
    ELF  Script Archive
     │     │     │
     └─────┼─────┘
           ↓
    Static Analyzer
           │
     ┌─────┼─────────────┐
     │     │             │
     ↓     ↓             ↓
 permissions strings  structure
     │     │             │
     ↓     ↓             ↓
   SUID   URLs/IP      sections
 executable commands   anomalies
           │
           ↓
       Indicators
           │
           ↓
       Risk Score

SF-006 — Surveillance des processus
Le système doit surveiller les processus démarrés et maintenir un contexte suffisant pour relier un processus à ses fichiers, processus enfants et connexions réseau.

Informations minimales :
• PID ;
• PPID ;
• utilisateur ;
• exécutable ;
• arguments ;
• hash de l’exécutable lorsqu’il est accessible ;
• heure de démarrage ;
• processus enfants ;
• événements de fichiers pertinents ;
• connexions réseau pertinentes.

Diagramme d’activité :

Programme exécuté
       │
       ↓
Process Monitor
       │
       ↓
Collecter
       │
       ├── executable
       ├── PID
       ├── parent PID
       ├── utilisateur
       ├── arguments
       └── hash executable
              │
              ↓
       Analyse comportement
              │
       ┌──────┼───────────┐
       ↓      ↓           ↓
    Fichiers  Processus  Réseau
    modifiés  enfants    connexions
       │      │           │
       └──────┼───────────┘
              ↓
        Risk Scoring
              │
              ↓
        Comportement
          dangereux ?
          /       \
        Non       Oui
        │          │
      Allow     Kill PID
                   │
                   ↓
                Alert

SF-007 — Détection comportementale simple
La V1 doit être capable de corréler plusieurs actions qui, prises isolément, peuvent être légitimes mais qui deviennent suspectes lorsqu’elles se produisent dans une même chaîne comportementale.

Exemples de signaux :
• accès inhabituel aux clés SSH ;
• lecture de secrets ;
• modification de fichiers système sensibles ;
• création en masse de processus enfants ;
• chiffrement ou modification massive de fichiers ;
• persistance inhabituelle ;
• connexion vers une destination identifiée comme IOC ;
• exfiltration potentielle caractérisée par une combinaison de signaux.

Diagramme d’activité :

Process inconnu démarre
        │
        ↓
Lit ~/.ssh/
        │
        ↓
Lit des clés privées
        │
        ↓
Compresse les fichiers
        │
        ↓
Contacte une IP inconnue
        │
        ↓
Transmet beaucoup de données
        │
        ↓
          ┌─────────────────────┐
          │ Chaque action seule │
          │ peut être légitime  │
          └──────────┬──────────┘
                     ↓
            Corrélation événements
                     ↓
              Score très élevé
                     ↓
               Process suspect
                     ↓
                 Kill process
                     ↓
                 Quarantaine

SF-008 — Surveillance réseau
Le système doit associer autant que possible une connexion réseau au processus qui l’a initiée. La V1 n’est pas un IDS réseau complet.

Données minimales :
• PID ;
• adresse IP destination ;
• port destination ;
• protocole ;
• domaine lorsqu’il est disponible ;
• heure ;
• décision IOC ;
• action éventuelle.

Diagramme d’activité :

Process
   │
   ↓
Connexion réseau
   │
   ↓
Network Monitor
   │
   ├── PID
   ├── IP destination
   ├── port
   ├── protocole
   └── domaine si disponible
          │
          ↓
      IOC Database
          │
          ↓
   IP/domaine connu ?
       /        \
     Non        Oui
      │          │
      ↓          ↓
Journaliser   Menace
                 │
                 ↓
            Bloquer connexion
                 │
                 ↓
             Risk Engine
                 │
                 ↓
            Kill process ?

SF-009 — Risk Engine
Toutes les sources de détection doivent converger vers un moteur de risque central. Les modules ne doivent pas décider indépendamment de supprimer un fichier.

Sources de score :
• hash ;
• YARA ;
• analyse statique ;
• comportement ;
• réseau ;
• IOC ;
• réputation ;
• contexte du processus.

Diagramme d’activité :

Hash Engine ──────────┐
                     │
YARA Engine ─────────┤
                     │
Static Analysis ─────┤
                     ↓
Behavior Engine ───► RISK ENGINE
                     ↑
Network Engine ──────┤
                     │
Threat Intelligence ─┘
                     │
                     ↓
               SCORE GLOBAL
                     │
         ┌───────────┼────────────┐
         ↓           ↓            ↓
       0-29        30-69        70-100
       LOW         SUSPICIOUS    MALICIOUS
         │           │            │
       Allow        Alert      Quarantine
                                  +
                                Kill

Les seuils 0-29 / 30-69 / 70-100 sont des valeurs initiales configurables et devront être calibrés par les tests.

SF-010 — Moteur de réponse
Le moteur de réponse exécute les actions décidées par le Risk Engine ou par une règle explicite de sécurité.

Actions V1 :
• autoriser ;
• alerter ;
• tuer un processus ;
• bloquer une connexion lorsque techniquement supporté ;
• mettre un fichier en quarantaine ;
• restaurer un fichier depuis la quarantaine ;
• supprimer définitivement un élément depuis la quarantaine sur action explicite.

SF-011 — Quarantaine
Un fichier détecté comme malveillant ne doit pas être supprimé automatiquement par défaut. Il doit être isolé dans une quarantaine protégée.

La quarantaine doit conserver :
• identifiant interne ;
• hash ;
• chemin original ;
• raison de détection ;
• score ;
• règles/indicateurs déclenchés ;
• date ;
• processus associé si disponible.

Diagramme d’activité :

Menace détectée
       │
       ↓
Response Engine
       │
       ↓
Process actif ?
   /       \
 Oui       Non
 │          │
 ↓          │
Kill PID    │
 │          │
 └────┬─────┘
      ↓
Déplacer fichier
      ↓
Répertoire quarantaine
      ↓
Retirer permissions
      ↓
Renommer / ID interne
      ↓
Enregistrer
      │
      ├── hash
      ├── chemin original
      ├── raison
      ├── date
      └── détections
             │
             ↓
       Notification UI

Restauration :

            Fichier en quarantaine
                     │
              ┌──────┴──────┐
              ↓             ↓
          Restaurer       Supprimer
              │             │
       avertissement     destruction
              │
              ↓
       chemin original

SF-012 — Threat Intelligence locale
La V1 doit maintenir une base locale contenant au minimum des IOC et hashes de malwares connus. Elle pourra être alimentée à partir de sources publiques compatibles avec le produit.

Données possibles :
• SHA-256 ;
• SHA-1 ;
• MD5 ;
• famille de malware ;
• type ;
• tags ;
• first_seen ;
• confidence ;
• IP ;
• domaine ;
• URL ;
• autres IOC pertinents.

Le moteur de détection ne doit pas transmettre chaque fichier de l’utilisateur à une API externe pour obtenir un verdict.

SF-013 — Mise à jour Threat Intelligence
L’Update Service doit télécharger, vérifier, normaliser et appliquer les mises à jour de données de Threat Intelligence.

Diagramme d’activité :

             Internet
                 │
      ┌──────────┼──────────┐
      ↓          ↓          ↓
MalwareBazaar ThreatFox   URLhaus
      │          │          │
      └──────────┼──────────┘
                 ↓
          Update Service
                 │
                 ↓
         Vérifier version
                 │
          nouvelle version ?
             /       \
           Non       Oui
           │          │
         Stop       Download
                      │
                      ↓
                  Vérifier
                  intégrité
                      │
                      ↓
                 Normaliser
                      │
                      ↓
               Threat DB locale

Principe de dépendance :

Internet
   ↓
Updater
   ↓
DB locale
   ↓
Detection Engine

SF-014 — Scan manuel
L’utilisateur doit pouvoir lancer un scan à la demande via l’interface ou la CLI.

Types minimaux :
• fichier ;
• dossier ;
• scan rapide ;
• scan complet.

Diagramme d’activité :

Utilisateur
    │
    ↓
"Scanner dossier"
    │
    ↓
Sélection dossier
    │
    ↓
Lister fichiers
    │
    ↓
Pour chaque fichier
    │
    ├─ Hash
    ├─ Threat DB
    ├─ YARA
    └─ Static analysis
         │
         ↓
     Risk Engine
         │
         ↓
┌────────┼────────┐
↓        ↓        ↓
Clean  Suspect  Malware
↓        ↓        ↓
         Alert   Quarantine
         │
         ↓
Rapport de scan

SF-015 — Journalisation des événements
Tous les événements importants doivent être journalisés de manière structurée.

Champs minimaux :
• timestamp ;
• event_type ;
• source/module ;
• PID et PPID si applicables ;
• utilisateur ;
• fichier ;
• hash ;
• destination réseau ;
• score ;
• sévérité ;
• détection ;
• action ;
• résultat de l’action.

Diagramme d’activité :

Security modules
       │
       ↓
   Event Bus
       │
       ↓
 Event Logger
       │
       ↓
Local Database
       │
       ├── timestamp
       ├── event_type
       ├── process
       ├── file
       ├── hash
       ├── destination
       ├── score
       ├── severity
       ├── detection
       └── action

Exemple de restitution :

19:02  chromium → google.com               ✓ NORMAL
19:04  update.sh → 185.xxx.xxx.xxx         ⚠ SUSPICIOUS
19:05  unknown.bin
       └─ YARA: Trojan.X
       └─ SHA256 reconnu
       └─ connexion IOC
       └─ Score: 98/100
       └─ QUARANTINED                      ✗ CRITICAL

SF-016 — Interface utilisateur locale
L’interface doit afficher au minimum :
• état général de protection ;
• état de l’agent ;
• état de la protection temps réel ;
• date/version de la Threat Database ;
• bouton de scan rapide ;
• bouton de scan complet ;
• nombre de fichiers analysés ;
• processus surveillés ;
• menaces bloquées ;
• connexions bloquées ;
• liste des incidents récents ;
• accès à la quarantaine ;
• accès aux détails d’un incident.

Maquette textuelle :

┌──────────────────────────────────────────────────┐
│                 SECURITY                         │
│                                                  │
│          ✓ VOTRE APPAREIL EST PROTÉGÉ            │
│                                                  │
│ Threat database : à jour                        │
│ Agent           : actif                         │
│ Protection      : temps réel                    │
│                                                  │
│ [ SCAN RAPIDE ]      [ SCAN COMPLET ]            │
│                                                  │
├──────────────────────────────────────────────────┤
│ Aujourd'hui                                      │
│                                                  │
│ Fichiers analysés                    2 481        │
│ Processus surveillés                  394        │
│ Menaces bloquées                        2        │
│ Connexions bloquées                     1        │
├──────────────────────────────────────────────────┤
│ Incidents                                        │
│                                                  │
│ 🔴 Trojan detected     18:42                     │
│ 🟡 Suspicious script   17:12                     │
└──────────────────────────────────────────────────┘

SF-017 — Explicabilité des détections
Chaque incident doit permettre de comprendre pourquoi une décision a été prise.

Une fiche incident doit afficher au minimum :
• objet concerné ;
• processus ;
• hash ;
• règle(s) YARA ;
• IOC correspondants ;
• indicateurs statiques ;
• comportements suspects ;
• score et contribution des principaux signaux ;
• action exécutée ;
• date et heure.

Le produit ne doit pas se limiter à afficher « Virus detected » sans justification exploitable.

7. RÈGLES DE GESTION

RG-001 — Un hash connu comme malveillant doit constituer un indicateur à très forte confiance.
RG-002 — Une correspondance YARA seule peut être configurée comme suspicion ou menace selon la règle.
RG-003 — La suppression automatique d’un fichier est désactivée par défaut.
RG-004 — Les décisions destructives doivent être centralisées dans le Response Engine.
RG-005 — Le Risk Engine doit accepter plusieurs signaux pour un même objet/processus.
RG-006 — Les seuils de risque sont configurables.
RG-007 — Les événements de sécurité doivent être horodatés.
RG-008 — Les mises à jour Threat Intelligence doivent être vérifiables avant activation.
RG-009 — Un échec de mise à jour ne doit pas rendre l’agent inutilisable avec la dernière base valide.
RG-010 — La quarantaine doit empêcher l’exécution accidentelle du fichier.
RG-011 — La restauration d’un fichier potentiellement dangereux doit présenter un avertissement.
RG-012 — La base locale ne doit pas nécessiter une consultation Internet par fichier analysé.

8. EXIGENCES NON FONCTIONNELLES

ENF-001 — Performance
La surveillance doit limiter l’impact sur CPU, mémoire et I/O. Les fichiers connus et inchangés doivent pouvoir bénéficier de mécanismes de cache afin d’éviter des analyses inutiles.

ENF-002 — Résilience
Une erreur d’un module non critique ne doit pas provoquer l’arrêt total du produit. L’état de protection dégradée doit être visible.

ENF-003 — Sécurité
Les composants privilégiés doivent être réduits au strict nécessaire. L’UI ne doit pas exécuter avec des privilèges root permanents.

ENF-004 — Intégrité
Les règles YARA, données Threat Intelligence et mises à jour doivent pouvoir être vérifiées avant chargement.

ENF-005 — Confidentialité
Les fichiers personnels ne doivent pas être téléversés vers un service tiers dans le flux standard de scan.

ENF-006 — Auditabilité
Toute action de blocage, kill, quarantaine, restauration ou suppression doit laisser une trace.

ENF-007 — Maintenabilité
Les moteurs doivent être séparés par interfaces afin de permettre l’ajout futur de Windows, Android, nouvelles sources IOC ou moteurs d’analyse.

ENF-008 — Configurabilité
Les chemins surveillés, exclusions, seuils de risque, fréquence de mise à jour et politiques de réponse doivent être configurables.

9. MODÈLE DE DONNÉES FONCTIONNEL MINIMAL

Entité Event :
• id ;
• timestamp ;
• event_type ;
• source_module ;
• pid ;
• ppid ;
• user ;
• file_path ;
• file_hash ;
• remote_ip ;
• remote_port ;
• domain ;
• severity ;
• score ;
• action ;
• result.

Entité ThreatIndicator :
• id ;
• indicator_type ;
• value ;
• malware_family ;
• confidence ;
• severity ;
• source ;
• first_seen ;
• last_seen ;
• tags ;
• enabled.

Entité Detection :
• id ;
• event_id ;
• detection_engine ;
• rule_id ;
• rule_name ;
• confidence ;
• score_contribution ;
• details.

Entité QuarantineItem :
• id ;
• original_path ;
• quarantine_path ;
• sha256 ;
• reason ;
• score ;
• quarantined_at ;
• restored_at ;
• deleted_at ;
• status.

Entité Scan :
• id ;
• scan_type ;
• target ;
• started_at ;
• completed_at ;
• files_scanned ;
• threats_found ;
• suspicious_found ;
• status.

10. CAS D’UTILISATION PRINCIPAUX

UC-001 — Protection temps réel
Acteur : système.
Déclencheur : création/modification/exécution/connexion.
Résultat : événement analysé et réponse adaptée.

UC-002 — Scanner un fichier
Acteur : utilisateur.
Résultat : verdict, score, détails et action proposée/exécutée.

UC-003 — Scanner un dossier
Acteur : utilisateur.
Résultat : rapport consolidé.

UC-004 — Consulter un incident
Acteur : utilisateur.
Résultat : chaîne explicative complète.

UC-005 — Consulter la quarantaine
Acteur : utilisateur.
Résultat : liste des éléments isolés et actions disponibles.

UC-006 — Restaurer un élément
Acteur : utilisateur autorisé.
Résultat : restauration contrôlée et auditée.

UC-007 — Mettre à jour les IOC
Acteur : Update Service.
Résultat : nouvelle base locale valide ou conservation de la précédente.

UC-008 — Consulter l’état de protection
Acteur : utilisateur.
Résultat : état agent, modules, base, dernière mise à jour et incidents.

11. FLUX DE DÉCISION DE RÉFÉRENCE

Un exemple de scoring illustratif :

Executable inconnu                     +10
+
YARA suspect                           +40
+
Tentative modification /etc/sudoers    +30
+
Connexion vers IOC malveillant          +80
                                         ───
                                      Score brut
                                         ↓
                                Normalisation / règles
                                         ↓
                                  SCORE DE RISQUE
                                         ↓
                           décision du Response Engine

Les valeurs ci-dessus sont illustratives et ne constituent pas le calibrage définitif.

12. CRITÈRES D’ACCEPTATION V1

La V1 est fonctionnellement acceptable lorsque :
• l’agent démarre automatiquement sur une machine Debian/Ubuntu supportée ;
• la protection temps réel détecte un nouveau fichier dans une zone surveillée ;
• un SHA-256 peut être comparé à la base locale ;
• une règle YARA peut produire une détection visible ;
• un fichier peut être analysé statiquement ;
• un processus et son PPID sont observables ;
• une connexion réseau peut être associée à un processus lorsque le système le permet ;
• plusieurs signaux peuvent être corrélés dans un même incident ;
• un score de risque est calculé ;
• un processus peut être tué sur décision du moteur de réponse ;
• un fichier peut être placé en quarantaine puis restauré ;
• les incidents sont enregistrés localement ;
• un scan manuel produit un rapport ;
• la base Threat Intelligence peut être mise à jour sans consultation distante par fichier ;
• l’interface affiche l’état général de protection ;
• une détection peut être expliquée par ses signaux et actions.

13. STRATÉGIE DE TEST

Tests unitaires :
• hash ;
• parsing IOC ;
• scoring ;
• YARA wrapper ;
• règles de décision ;
• stockage.

Tests d’intégration :
• monitor → event engine ;
• event engine → detection engines ;
• detection → risk engine ;
• risk engine → response engine ;
• response → logger/quarantaine ;
• updater → threat DB.

Tests fonctionnels :
• fichier propre ;
• hash connu ;
• YARA test ;
• script suspect ;
• création massive de fichiers ;
• comportement simulé d’accès à un répertoire sensible ;
• connexion vers IOC de test ;
• quarantaine/restauration ;
• panne de l’updater ;
• base locale absente/corrompue ;
• protection dégradée.

Les tests doivent utiliser des fichiers de test sûrs ou des artefacts spécialement conçus pour la validation. Les véritables échantillons de malware ne doivent pas être exécutés sur la machine de développement.

14. DÉFINITION SYNTHÉTIQUE DE LA V1

La V1 doit détecter qu’un fichier, processus ou comportement dangereux apparaît sur une machine Linux, corréler les indices disponibles, attribuer un niveau de risque, stopper la menace lorsque nécessaire et conserver suffisamment de preuves pour expliquer pourquoi elle a été bloquée.

15. ÉVOLUTION ENVISAGÉE APRÈS LA V1

V2 possible :
• agent Windows ;
• enrichissement comportemental ;
• meilleures capacités de réponse ;
• signature et distribution sécurisée des mises à jour.

V3 possible :
• console centrale ;
• gestion de plusieurs machines ;
• incidents centralisés ;
• threat hunting ;
• historique ;
• IOC internes ;
• premières fonctions EDR.

V4 possible :
• Android ;
• protection DNS / phishing ;
• extensions de détection réseau ;
• orchestration avancée.

FIN DU DOCUMENT

