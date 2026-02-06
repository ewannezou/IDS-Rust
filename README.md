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
- WebEnum
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
- Une VM Ubuntu Server

## Installation
Pour récupérer le dépot : 

``git clone https://github.com/ewannezou/IDS-Rust``

``cd ids``

Executez la commande ``cargo build --release`` pour compiler le fichier, puis récuperer le fichier binaire``ids-rust`` dans le dossier : ``/target/release/ids-rust``

Dans votre Ubuntu Server, créer un répertoire ``/opt/ids/`` et placez-y le fichier ``rust-ids``

Puis ajoutez un utilisateur dédié à l'IDS avec les commandes : 

``sudo useradd -r -s /bin/false monids``

``sudo usermod -aG adm monids``

``sudo chown monids:monids /opt/ids/rust-ids``

Et enfin, autorisez la capture réseau avec la commmande :

``sudo setcap cap_net_raw,cap_net_admin+eip /opt/ids/rust-ids``



## Utilisation
Pour activez L'IDS, lancer la commande : 

``sudo -u monids /opt/ids/rust-ids``

## Construit avec

### Langages & Frameworks

[Liste de tout ce qui permet la confection du projet avec description + lien vers la documentation]

#### Déploiement

[Liste de tout ce qui permet le déploiement du projet avec description + lien vers la documentation et mise en avant des comptes, organisations et variables]

## Documentation

Lien vers le fichier [Documentation](./doc_ids-rust) du dépôt

## Licence

Voir le fichier [LICENSE](./LICENSE.md) du dépôt.

  
