#!/bin/bash

set -e

SERVICE_NAME="monids"
BIN_NAME="rust-ids"
INSTALL_DIR="/opt/ids"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BIN_PATH="${INSTALL_DIR}/${BIN_NAME}"
LOG_DIR="/opt/log/ids"
LOG_FILE="${LOG_DIR}/ids_alert.log"

echo "Installation de MON IDS..."

if [ "$EUID" -ne 0 ]; then
  echo "Ce script doit être exécuté en mode root"
  exit 1
fi

if ! id monids &>/dev/null; then
  echo "Création de l'utilisateur système monids"
  useradd -r -s /bin/false monids
  usermod -aG adm monids
else
  echo "Utilisateur monids déjà existant"
fi

echo "📁 Création des dossiers "

mkdir -p ${INSTALL_DIR}
mkdir -p ${LOG_DIR}

touch ${LOG_FILE}

chown monids:adm ${LOG_DIR}
chown monids:adm ${LOG_FILE}

chmod 750 ${LOG_DIR}
chmod 640 ${LOG_FILE}

if [ ! -f "${BIN_NAME}" ]; then
  echo " Binaire ${BIN_NAME} introuvable dans le dossier courant"
  echo " Copie le binaire ici avant de lancer le script"
  exit 1
fi

echo "Installation du binaire"
cp ${BIN_NAME} ${BIN_PATH}
chmod 750 ${BIN_PATH}
chown monids:monids ${BIN_PATH}

echo "Création du service systemd"

cat <<EOF > ${SERVICE_FILE}
[Unit]
Description=MON IDS (Rust)
After=network.target

[Service]
Type=simple
User=monids
Group=adm
ExecStart=${BIN_PATH}

# Autorisation capture réseau
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# Sécurité 
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadOnlyPaths=/var/log

Restart=always
RestartSec=5

WantedBy=multi-user.target
EOF

echo "🔄 Rechargement systemd"
systemctl daemon-reexec
systemctl daemon-reload

echo "Activation et démarrage du service"
systemctl enable ${SERVICE_NAME}
systemctl restart ${SERVICE_NAME}

echo "Installation terminée"
systemctl status ${SERVICE_NAME} --no-pager

echo ""
echo "Commande pour voir les logs en direct :"
echo "   journalctl -u ${SERVICE_NAME} -f"
