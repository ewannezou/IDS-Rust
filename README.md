# IDS-Rust

## À propos

🛡️ Purple Team Lab – Système de Détection d’Attaques Réseaux

🎯 Objectif du projet

Ce projet consiste à concevoir et déployer un lab Purple Team afin de :

- Simuler des attaques réalistes

- Observer et analyser les traces laissées dans les logs

- Mettre en place des mécanismes de détection et de défense

👉 L’objectif est de comprendre le cycle complet attaque → détection → mitigation.

Attaque détéctées : 
- Web Enumeration
- PortScan
- SSH Brute-Force
- DDOS

## Table des matières

- 🪧 [À propos](#à-propos)
- 📦 [Prérequis](#prérequis)
- 🚀 [Installation](#installation)
- 🛠️ [Utilisation](#utilisation)
- 🏗️ [Construit avec](#construit-avec)
- 📚 [Documentation](#documentation)
- 📝 [Licence](#licence)

## Prérequis

- Rust version > 1.83
- Voir le fichier [Documentation](./doc_ids-rust) du dépôt
- Une VM Ubuntu Server (cible)
- Une VM Kali Linux pour simuler des attaques sur la cible (attaquant)

## Installation
Pour récupérer le dépot : 

``git clone https://github.com/ewannezou/IDS-Rust``

Télécharger le dossier ``/deploy`` sur votre Server Ubuntu (dans le répertoire ``/tmp`` par exemple).

Entrez dans le dossier ``/deploy`` avec la commande : ``cd deploy``

Puis éxécutez la commande ``sudo ./install.sh ``

L'IDS s'installera automatiquement en tant que service sur votre Server Ubunutu avec l'utilisateur ``monids``


## Utilisation
Pour voir les logs en direct de L'IDS, utiliser la commande : ``journalctl -u monids -f``

Pour voir l'historique des logs, accéder au fichier ``ids_alert.log`` qui se trouve dans le répertoire : ``/opt/log/ids/ids_alert.log``

## Construit avec

### Langages & Frameworks

- Rust
- Voir le fichier des librairies utilisées [Cargo.toml](./code_source/ids/Cargo.toml)


## Documentation

Lien vers le fichier [Documentation](./doc_ids-rust) du dépôt

## Licence

Voir le fichier [LICENSE](./LICENSE.md) du dépôt.

  
