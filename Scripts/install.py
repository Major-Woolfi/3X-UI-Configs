import importlib
import subprocess
import sys

REQUIREMENTS = ["cryptography>=50.0.0"]


def check_module(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False


def install() -> bool:
    missing = []
    for req in REQUIREMENTS:
        pkg = req.split(">=")[0].split("=")[0].strip()
        top_level = pkg.replace("-", "_")
        if not check_module(top_level) and not check_module(pkg):
            missing.append(req)

    if not missing:
        print("[OK] Все зависимости уже установлены")
        return True

    print(f"[INFO] Установка: {', '.join(missing)}")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", *missing],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        print(f"[ОШИБКА] pip install не удалось: {e}")
        return False

    for req in missing:
        pkg = req.split(">=")[0].split("=")[0].strip()
        top_level = pkg.replace("-", "_")
        if not check_module(top_level) and not check_module(pkg):
            print(f"[ОШИБКА] {pkg} установлен, но не импортируется")
            return False

    print("[OK] Все зависимости установлены")
    return True


if __name__ == "__main__":
    ok = install()
    sys.exit(0 if ok else 1)
