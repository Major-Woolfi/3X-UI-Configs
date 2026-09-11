import base64
import json
import logging
import os
import re
import secrets
import sys
import uuid
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, dict, list, tuple

# --- Константы ---
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
CONFIGS_DIR = ROOT_DIR / "Configs"
BUILD_DIR = ROOT_DIR / "Build"
LOG_DIR = ROOT_DIR / "logs"

HEX_PLACEHOLDER_RE = re.compile(r"^\s*(\d+)\s*HEX", re.IGNORECASE)

# --- Логирование ---
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = TimedRotatingFileHandler(
    os.path.join(LOG_DIR, f"{__name__}.log"),
    when="midnight",
    encoding="utf-8",
)
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

# --- Настройка консоли для Windows ---
if sys.platform == "win32":
    for _s in ("stdout", "stderr", "stdin"):
        try:
            getattr(sys, _s).reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001, S110
            pass

# --- Проверка доступности библиотек ---
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography не установлена, используется чистая реализация X25519")

try:
    import oqs

    HAS_OQS = True
except ImportError:
    HAS_OQS = False
    logger.warning("liboqs-python не установлена, ML-KEM-768 будет использовать случайные байты")


# --- X25519 (Reality: privateKey / publicKey) ---
def _x25519_pure(k: bytes, u: bytes) -> bytes:
    p = 2**255 - 19
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")
    u_int = int.from_bytes(u, "little") % p

    def cswap(swap: int, x: int, y: int) -> tuple[int, int]:
        dummy = (swap * (x - y)) % p
        return (x - dummy) % p, (y + dummy) % p

    x_2, z_2 = 1, 0
    x_3, z_3 = u_int, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (k_int >> t) & 1
        swap ^= bit
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = bit
        A = (x_2 + z_2) % p
        AA = A * A % p
        B = (x_2 - z_2) % p
        BB = B * B % p
        E = (AA - BB) % p
        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p
        DA = D * A % p
        CB = C * B % p
        x_3 = pow((DA + CB) % p, 2, p)
        z_3 = u_int * pow((DA - CB) % p, 2, p) % p
        x_2 = AA * BB % p
        z_2 = E * (AA + 121665 * E) % p
    x_2, _ = cswap(swap, x_2, x_3)
    z_2, _ = cswap(swap, z_2, z_3)
    return (x_2 * pow(z_2, p - 2, p) % p).to_bytes(32, "little")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def gen_reality_keypair() -> tuple[str, str]:
    if HAS_CRYPTO:
        po = X25519PrivateKey.generate()
        priv = po.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub = po.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    else:
        priv = secrets.token_bytes(32)
        pub = _x25519_pure(priv, b"\x09" + b"\x00" * 31)
    return _b64url(priv), _b64url(pub)


# --- ML-KEM-768 (гибридный KEM: ML-KEM-768 + X25519) ---
def gen_mlkem768_keys() -> tuple[str, str]:
    """
    Генерирует ключи для mlkem768x25519plus.

    Формат 3X-UI:
    - decryption: mlkem768x25519plus.random.600s.<base64url(64 байта)>
    - encryption: mlkem768x25519plus.random.0rtt.<base64url(1184 байта)>

    64 байта = seed для ML-KEM-768 private key
    1184 байта = ML-KEM-768 public key
    """
    if HAS_OQS:
        # Настоящая генерация через liboqs
        seed = secrets.token_bytes(64)
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair_seed(seed)
        logger.debug(
            f"ML-KEM-768 сгенерирован через liboqs (seed: {len(seed)} байт, pk: {len(public_key)} байт)"
        )
    else:
        # Fallback: случайные байты нужной длины
        seed = secrets.token_bytes(64)
        public_key = secrets.token_bytes(1184)
        logger.warning("ML-KEM-768 сгенерирован случайными байтами (liboqs не установлен)")

    decryption = f"mlkem768x25519plus.random.600s.{_b64url(seed)}"
    encryption = f"mlkem768x25519plus.random.0rtt.{_b64url(public_key)}"
    return decryption, encryption


# --- Генерация секретов ---
def gen_short_id() -> str:
    """6 байт = 12 hex символов"""
    return secrets.token_hex(6)


def gen_hex(n_bytes: int) -> str:
    return secrets.token_hex(n_bytes)


def gen_uuid() -> str:
    return str(uuid.uuid4())


def gen_password() -> str:
    return secrets.token_urlsafe(16)


def gen_ss_password() -> str:
    return _b64url(secrets.token_bytes(32))


def gen_mtproto_secret() -> str:
    return "ee" + secrets.token_hex(16)


def gen_spider_x_path() -> str:
    """/<15 hex символов>"""
    return "/" + secrets.token_hex(8)[:15]


def gen_hex_from_placeholder(v: str) -> str | None:
    m = HEX_PLACEHOLDER_RE.match(v.strip())
    if not m:
        return None
    n = int(m.group(1))
    return secrets.token_hex(max(1, n // 2))


# --- Определение типа / заполнение ---
def is_whitelist_quick(cfg_path: Path) -> bool:
    if "whitelist" in cfg_path.name.lower():
        return True
    try:
        txt = cfg_path.read_text(encoding="utf-8")
        return "YOURDOMAIN.CLIENT.INHERE" in txt or "YOURDOMAIN.SERVER.INHERE" in txt
    except Exception:  # noqa: BLE001
        return False


def fill_config(
    config: dict[str, Any],
    client_domain: str | None = None,
    server_domain: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol = config.get("protocol", "")
    stream = config.get("streamSettings", {}) or {}
    security = stream.get("security", "")
    network = stream.get("network", "")
    generated: dict[str, Any] = {}

    # Reality: privateKey / publicKey / shortId / spiderX
    if security == "reality":
        priv, pub = gen_reality_keypair()
        generated["privateKey"] = priv
        generated["publicKey"] = pub
        generated["shortId"] = gen_short_id()
        generated["spiderX"] = gen_spider_x_path()

    # ML-KEM-768: генерируем пару encryption/decryption
    mlkem_decryption, mlkem_encryption = gen_mlkem768_keys()
    generated["mlkem_decryption"] = mlkem_decryption
    generated["mlkem_encryption"] = mlkem_encryption

    # XHTTP-паддинг
    if network == "xhttp":
        generated["xPaddingKey"] = gen_hex(16)
        generated["sessionIDKey"] = gen_hex(16)
        generated["seqKey"] = gen_hex(8)

    # Клиенты
    if protocol == "vless":
        cid = gen_uuid()
        client = {"id": cid, "flow": "", "email": "generated-client"}
        config.setdefault("settings", {})["clients"] = [client]
        generated["client_id"] = cid
        generated["flow"] = ""
    elif protocol == "trojan":
        pwd = gen_password()
        config.setdefault("settings", {})["clients"] = [
            {"password": pwd, "email": "generated-client"}
        ]
        generated["client_password"] = pwd
    elif protocol == "shadowsocks":
        pwd = gen_ss_password()
        config.setdefault("settings", {})["password"] = pwd
        generated["ss_password"] = pwd
    elif protocol == "mtproto":
        sec = gen_mtproto_secret()
        config.setdefault("settings", {})["users"] = [{"secret": sec}]
        generated["mtproto_secret"] = sec

    def transform_string(v: str, key: str) -> str:
        # ML-KEM-768 (decryption/encryption)
        if key == "decryption" and isinstance(v, str) and "(random)" in v:
            return mlkem_decryption
        if key == "encryption" and isinstance(v, str) and "(random)" in v:
            return mlkem_encryption
        # Reality
        if key == "privateKey" and v == "REGENERATE PLS":
            return generated.get("privateKey", v)
        if key == "publicKey" and v == "REGENERATE PLS":
            return generated.get("publicKey", v)
        if key == "spiderX":
            if v == "REGENERATE PLS" or v == "":
                return generated.get("spiderX", gen_spider_x_path())
            return v
        # shortIds
        if key == "shortIds" and isinstance(v, list):
            return [generated.get("shortId", x) if x == "REGENERATE PLS" else x for x in v]
        # Известные hex-ключи
        if key == "xPaddingKey":
            return generated.get("xPaddingKey", gen_hex(16))
        if key == "sessionIDKey":
            return generated.get("sessionIDKey", gen_hex(16))
        if key == "seqKey":
            return generated.get("seqKey", gen_hex(8))
        # Любые прочие *HEX* плейсхолдеры
        hx = gen_hex_from_placeholder(v)
        if hx is not None:
            return hx
        if v == "REGENERATE PLS":
            return gen_password()
        # Домены
        if client_domain:
            v = v.replace("YOURDOMAIN.CLIENT.INHERE", client_domain)
        if server_domain:
            v = v.replace("YOURDOMAIN.SERVER.INHERE", server_domain)
        return v

    def walk(obj: Any, key: str | None = None) -> Any:
        if isinstance(obj, dict):
            return {k: walk(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            if key == "shortIds" and security == "reality":
                return [generated.get("shortId", x) if x == "REGENERATE PLS" else x for x in obj]
            return [walk(x, key) for x in obj]
        if isinstance(obj, str):
            return transform_string(obj, key)
        return obj

    return walk(config), generated


def find_remaining_placeholders(obj: Any, found: list[str] | None = None) -> list[str]:
    if found is None:
        found = []
    if isinstance(obj, dict):
        for v in obj.values():
            find_remaining_placeholders(v, found)
    elif isinstance(obj, list):
        for x in obj:
            find_remaining_placeholders(x, found)
    elif isinstance(obj, str):  # noqa: SIM102
        if obj in ("REGENERATE PLS",) or HEX_PLACEHOLDER_RE.match(obj.strip()):
            found.append(obj)
    return found


# --- Пакетный выбор ---
def parse_selection(text: str, count: int) -> list[int]:
    text = text.strip().lower()
    if text in ("all", "все", "*", "a", "всё"):
        return list(range(1, count + 1))
    selected: set = set()
    text = text.replace(",", " ").replace(";", " ").replace("\t", " ")
    for token in text.split():
        if not token:
            continue
        if "-" in token:
            parts = token.split("-")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                lo, hi = sorted((int(parts[0]), int(parts[1])))
                selected.update(i for i in range(lo, hi + 1) if 1 <= i <= count)
        elif token.isdigit():
            i = int(token)
            if 1 <= i <= count:
                selected.add(i)
    return sorted(selected)


def choose_configs(configs: list[Path]) -> list[Path]:
    print("\nДоступные конфиги:\n")
    for i, cfg in enumerate(configs, 1):
        mark = " [WL]" if is_whitelist_quick(cfg) else ""
        print(f"  {i:>2}. {cfg.stem}{mark}")
    print("\nВвод: номера через запятую/пробел, диапазоны (напр. '1,3,5-7'), или 'all'")
    while True:
        sel = parse_selection(input("Выбор: "), len(configs))
        if sel:
            return [configs[i - 1] for i in sel]
        print("Ничего не выбрано, попробуйте снова.")


def process_one(selected: Path, client_domain: str | None, server_domain: str | None) -> None:
    logger.info(f"Обработка: {selected.name}")
    print(f"\n>>> {selected.name}")
    with open(selected, "r", encoding="utf-8") as f:
        config = json.load(f)

    config, generated = fill_config(config, client_domain, server_domain)

    left = find_remaining_placeholders(config)
    if left:
        logger.warning(f"Остались плейсхолдеры: {sorted(set(left))}")
        print(f"   [ВНИМАНИЕ] Остались плейсхолдеры: {sorted(set(left))}")

    BUILD_DIR.mkdir(exist_ok=True)
    out_path = BUILD_DIR / selected.name
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"   [OK] Готовый конфиг сохранён: {out_path.name}")
    logger.info(f"Конфиг сохранён: {out_path}")

    # Выводим секреты в консоль
    print("   Сгенерированные секреты:")
    for k, v in generated.items():
        print(f"     {k}: {v}")


def main() -> None:
    logger.info("Запуск генератора конфигов")
    print("=" * 62)
    print("  XRay / 3X-UI Config Generator  (batch v5)")
    print("=" * 62)
    xm = "библиотека `cryptography`" if HAS_CRYPTO else "чистая реализация RFC 7748"
    mlkem = "liboqs-python (настоящая ML-KEM-768)" if HAS_OQS else "случайные байты"
    print(f"  X25519 для Reality : {xm}")
    print(f"  ML-KEM-768         : {mlkem}")

    if not CONFIGS_DIR.exists():
        logger.error(f"Папка '{CONFIGS_DIR}' не найдена")
        print(f"\n[ОШИБКА] Папка '{CONFIGS_DIR}' не найдена.")
        return
    configs = sorted(CONFIGS_DIR.glob("*.json"))
    if not configs:
        logger.error(f"В '{CONFIGS_DIR}' нет .json файлов")
        print(f"\n[ОШИБКА] В '{CONFIGS_DIR}' нет .json файлов.")
        return

    while True:
        selected = choose_configs(configs)
        client_domain = server_domain = None
        if any(is_whitelist_quick(p) for p in selected):
            print("\nСреди выбранных есть WhiteList/CDN конфиги.")
            print("Домены будут применены ко ВСЕМ WL-конфигам партии.")
            client_domain = input("  Домен КЛИЕНТА (публичный): ").strip()
            server_domain = input("  Домен СЕРВЕРА (на сервер): ").strip()

        for path in selected:
            process_one(path, client_domain, server_domain)

        print("\nПакет обработан.")
        logger.info("Пакет обработан")
        if input("\nСгенерировать ещё партию? (y/n): ").strip().lower() not in (
            "y",
            "yes",
            "д",
            "да",
        ):
            break
    print("\nГотово!")
    logger.info("Генератор завершён")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nОтменено пользователем.")
        logger.info("Отменено пользователем")
    except Exception as e:
        logger.exception(f"Критическая ошибка: {e}")  # noqa: TRY401
        print(f"\n[ОШИБКА] {e}")
        import traceback

        traceback.print_exc()
    input("\nНажмите Enter для выхода...")
