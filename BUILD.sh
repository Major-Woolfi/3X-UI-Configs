cd "$(dirname "$0")" || exit 1

if ! command -v python3 &>/dev/null; then
    echo "[ОШИБКА] python3 не найден. Установите Python 3.9+."
    exit 1
fi

export PYTHONIOENCODING=utf-8
python3 Scripts/generate_config.py