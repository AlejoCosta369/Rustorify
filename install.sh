#!/usr/bin/env bash
# install.sh — Instala rustorify y sus dependencias en sistemas Debian/Ubuntu/Kali
set -euo pipefail

# ─── Colores ────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

# ─── Banner ─────────────────────────────────────────────────────────────────

echo -e "${RED}"
cat << 'EOF'
        /\_____/\
       /  -     -  \
      ( |  /   \  | )
  ----( |  \___/  | )----
 /    \ \         / /    \
/  /\  \_\_______/_/  /\  \
\ /  \_______________/  \ /
 V    r u s t o r i f y  V
EOF
echo -e "${RESET}"

# ─── Root ───────────────────────────────────────────────────────────────────

if [[ "$EUID" -ne 0 ]]; then
    error "Este script debe ejecutarse como root. Usa: sudo bash install.sh"
fi

# ─── Detectar distro ────────────────────────────────────────────────────────

if ! command -v apt-get &>/dev/null; then
    error "Solo se soportan sistemas basados en Debian/Ubuntu/Kali (apt)."
fi

# ─── Dependencias del sistema ────────────────────────────────────────────────

info "Instalando dependencias del sistema..."
apt-get update -qq
apt-get install -y --no-install-recommends tor iptables curl
ok "Dependencias instaladas: tor, iptables, curl"

# ─── Rust ───────────────────────────────────────────────────────────────────

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
CARGO_BIN="$REAL_HOME/.cargo/bin/cargo"

if command -v cargo &>/dev/null || [[ -x "$CARGO_BIN" ]]; then
    ok "Rust/Cargo ya está instalado"
else
    info "Instalando Rust para el usuario '$REAL_USER'..."
    sudo -u "$REAL_USER" bash -c \
        'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path'
    ok "Rust instalado"
fi

# Asegurarse de que cargo esté en el PATH para este script
export PATH="$REAL_HOME/.cargo/bin:$PATH"

if ! command -v cargo &>/dev/null; then
    error "cargo no encontrado después de instalar Rust. Reinicia el terminal y vuelve a ejecutar."
fi

# ─── Compilar ───────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

info "Compilando rustorify (modo release)..."
sudo -u "$REAL_USER" "$REAL_HOME/.cargo/bin/cargo" build --release
ok "Compilación exitosa"

# ─── Instalar binario y datos ────────────────────────────────────────────────

info "Instalando binario en /usr/local/bin/rustorify..."
cp target/release/rustorify /usr/local/bin/rustorify
chmod 755 /usr/local/bin/rustorify
ok "Binario instalado"

info "Instalando archivos de datos..."
mkdir -p /usr/share/rustorify/data
cp data/torrc /usr/share/rustorify/data/torrc

mkdir -p /var/lib/rustorify/backups
ok "Archivos de datos instalados"

# ─── Listo ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}  rustorify instalado correctamente${RESET}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo "  Uso:"
echo "    sudo rustorify --tor            # Activar proxy Tor"
echo "    sudo rustorify --tor --kill-switch  # Con kill switch"
echo "    sudo rustorify --clearnet       # Desactivar y restaurar"
echo "    sudo rustorify --status         # Ver estado"
echo "    sudo rustorify --ipinfo         # Ver IP pública"
echo ""
