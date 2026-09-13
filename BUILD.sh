cd "$(dirname "$0")" || exit 1

if ! command -v python3 &>/dev/null; then
    echo "[ОШИБКА] python3 не найден. Установите Python 3.9+."
    exit 1
fi

export PYTHONIOENCODING=utf-8

echo "[INFO] Проверка зависимостей..."
if ! python3 Scripts/install.py; then
    echo "[ОШИБКА] Не удалось установить зависимости."
    exit 1
fi

python3 Scripts/generate_config.py