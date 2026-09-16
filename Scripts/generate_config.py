import argparse
import base64
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# --- Константы ---
SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
CONFIGS_DIR = ROOT_DIR / "Configs"
BUILD_DIR = ROOT_DIR / "Build"

HEX_PLACEHOLDER_RE = re.compile(r"^\s*(\d+)\s*HEX", re.IGNORECASE)
DOMAIN_PLACEHOLDERS = ("YOURDOMAIN.CLIENT.INHERE", "YOURDOMAIN.SERVER.INHERE")

# 3x-ui хранит эти протоколы в структурах, которые генератор соберёт только
# угадыванием (mtproto - ee-secret с доменом, wireguard/amneziawg - wg-ключи).
SKIP_PROTOCOLS = {"mtproto", "wireguard", "amneziawg", "dokodemo-door", "http", "socks"}

# VLESS Encryption: mlkem768x25519plus.<вид трафика>.<ticket|rtt>.<ключ>
# Ключ аутентификации (decryption) - 64 байта: shared secret из ML-KEM-768 (32) + X25519 (32).
# Ключ шифрования (encryption) - 1184 байта ML-KEM-768 public key (base64url).
VLESS_ENC_METHOD = "mlkem768x25519plus"
VLESS_ENC_APPEARANCE = "random"
VLESS_ENC_INBOUND_TTL = "600s"
VLESS_ENC_OUTBOUND_RTT = "0rtt"


# --- Настройка консоли для Windows ---
if sys.platform == "win32":
    for _stream_name in ("stdout", "stderr", "stdin"):
        try:
            getattr(sys, _stream_name).reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001, S110
            pass

# --- Проверка доступности библиотек ---
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# --- X25519 pure math (fallback при отсутствии cryptography) ---
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
        a = (x_2 + z_2) % p
        aa = a * a % p
        b = (x_2 - z_2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x_3 + z_3) % p
        d = (x_3 - z_3) % p
        da = d * a % p
        cb = c * b % p
        x_3 = pow((da + cb) % p, 2, p)
        z_3 = u_int * pow((da - cb) % p, 2, p) % p
        x_2 = aa * bb % p
        z_2 = e * (aa + 121665 * e) % p
    x_2, _ = cswap(swap, x_2, x_3)
    z_2, _ = cswap(swap, z_2, z_3)
    return (x_2 * pow(z_2, p - 2, p) % p).to_bytes(32, "little")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def gen_x25519_keypair() -> tuple[str, str]:
    if HAS_CRYPTO:
        private_obj = X25519PrivateKey.generate()
        priv = private_obj.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pub = private_obj.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    else:
        priv = secrets.token_bytes(32)
        pub = _x25519_pure(priv, b"\x09" + b"\x00" * 31)
    return _b64url(priv), _b64url(pub)


# --- X25519 (Reality) ---
def gen_reality_keypair() -> tuple[str, str]:
    return gen_x25519_keypair()


@lru_cache(maxsize=1)
def _vlessenc_from_xray() -> tuple[str, str] | None:
    binary = os.environ.get("XRAY_BIN") or shutil.which("xray")
    if not binary:
        return None
    try:
        result = subprocess.run(
            [binary, "vlessenc"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    text = result.stdout + result.stderr
    decryption = re.search(r'"decryption"\s*:\s*"([^"]+)"', text)
    encryption = re.search(r'"encryption"\s*:\s*"([^"]+)"', text)
    if not decryption or not encryption:
        return None
    return decryption.group(1), encryption.group(1)


def gen_vless_enc_pair() -> tuple[str, str, str]:
    pair = _vlessenc_from_xray()
    if pair:
        return pair[0], pair[1], "xray vlessenc"
    try:
        from cryptography.hazmat.primitives import serialization as crypto_serialization
        from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

        mlkem = MLKEM768PrivateKey.generate()
        seed = mlkem.private_bytes(
            crypto_serialization.Encoding.Raw,
            crypto_serialization.PrivateFormat.Raw,
            crypto_serialization.NoEncryption(),
        )
        pub = mlkem.public_key().public_bytes(
            crypto_serialization.Encoding.Raw,
            crypto_serialization.PublicFormat.Raw,
        )
        decryption = (
            f"{VLESS_ENC_METHOD}.{VLESS_ENC_APPEARANCE}.{VLESS_ENC_INBOUND_TTL}.{_b64url(seed)}"
        )
        encryption = (
            f"{VLESS_ENC_METHOD}.{VLESS_ENC_APPEARANCE}.{VLESS_ENC_OUTBOUND_RTT}.{_b64url(pub)}"
        )
        return decryption, encryption, "ML-KEM-768 (random)"
    except (ImportError, Exception) as e:  # noqa: BLE001
        logger.warning("ML-KEM-768 generation failed (%s), using random bytes", e)
        return (
            f"{VLESS_ENC_METHOD}.{VLESS_ENC_APPEARANCE}.{VLESS_ENC_INBOUND_TTL}.{_b64url(secrets.token_bytes(64))}",
            f"{VLESS_ENC_METHOD}.{VLESS_ENC_APPEARANCE}.{VLESS_ENC_OUTBOUND_RTT}.{_b64url(secrets.token_bytes(1184))}",
            "ML-KEM-768 (random, нужен xray для точных ключей)",
        )


# --- Генерация секретов ---
def gen_short_id() -> str:
    length = secrets.randbelow(8) + 1
    return secrets.token_hex(length)


def gen_password() -> str:
    return secrets.token_urlsafe(16)


def gen_ss_password(method: str) -> str:
    # У 2022-blake3-* пароль - это base64 ключ фиксированной длины, а не строка.
    if "2022-blake3" in method:
        n_bytes = 16 if "128" in method else 32
        return base64.b64encode(secrets.token_bytes(n_bytes)).decode()
    return secrets.token_urlsafe(22)


def gen_hex_from_placeholder(value: str) -> str | None:
    match = HEX_PLACEHOLDER_RE.match(value.strip())
    if not match:
        return None
    n_hex = int(match.group(1))
    return secrets.token_hex(max(1, n_hex // 2))


# --- Схема панели 3x-ui v3.7.0 / XRay-core v26.9.9: типы полей ---
STR = "str"
INT = "int"
BOOL = "bool"
DICT = "dict"
OPEN = "open"

XHTTP_SPEC: dict[str, Any] = {
    "path": STR,
    "host": STR,
    "mode": "enum:auto|packet-up|stream-up|stream-one",
    "xPaddingBytes": STR,
    "xPaddingObfsMode": BOOL,
    "xPaddingKey": STR,
    "xPaddingHeader": STR,
    "xPaddingPlacement": STR,
    "xPaddingMethod": STR,
    "sessionIDPlacement": STR,
    "sessionIDKey": STR,
    "sessionIDTable": STR,
    "sessionIDLength": STR,
    "seqPlacement": STR,
    "seqKey": STR,
    "uplinkDataPlacement": STR,
    "uplinkDataKey": STR,
    "scMaxEachPostBytes": STR,
    "noSSEHeader": BOOL,
    "scMaxBufferedPosts": INT,
    "scStreamUpServerSecs": STR,
    "serverMaxHeaderBytes": INT,
    "uplinkHTTPMethod": STR,
    "headers": DICT,
    "scMinPostsIntervalMs": STR,
    "uplinkChunkSize": INT,
    "noGRPCHeader": BOOL,
    "xmux": {
        "maxConcurrency": STR,
        "maxConnections": "str|int",
        "cMaxReuseTimes": "str|int",
        "hMaxRequestTimes": STR,
        "hMaxReusableSecs": STR,
        "hKeepAlivePeriod": INT,
    },
    "enableXmux": BOOL,
}

TLS_SPEC: dict[str, Any] = {
    "serverName": STR,
    "minVersion": "enum:1.0|1.1|1.2|1.3",
    "maxVersion": "enum:1.0|1.1|1.2|1.3",
    "cipherSuites": STR,
    "rejectUnknownSni": BOOL,
    "disableSystemRoot": BOOL,
    "enableSessionResumption": BOOL,
    "certificates": "list<dict>",
    "alpn": "list<str>",
    "echServerKeys": STR,
    "curvePreferences": "list<str>",
    "masterKeyLog": "opt:str",
    "settings": {
        "fingerprint": STR,
        "echConfigList": STR,
        "pinnedPeerCertSha256": "list<str>",
        "verifyPeerCertByName": STR,
    },
}

REALITY_SPEC: dict[str, Any] = {
    "show": BOOL,
    "xver": INT,
    "target": STR,
    "serverNames": "list<str>",
    "privateKey": STR,
    "minClientVer": STR,
    "maxClientVer": STR,
    "maxTimediff": INT,
    "shortIds": "list<str>",
    "mldsa65Seed": STR,
    "masterKeyLog": "opt:str",
    "limitFallbackUpload": "opt:dict",
    "limitFallbackDownload": "opt:dict",
    "settings": {
        "publicKey": STR,
        "fingerprint": STR,
        "serverName": STR,
        "mldsa65Verify": STR,
    },
}

SOCKOPT_SPEC: dict[str, Any] = {
    "acceptProxyProtocol": BOOL,
    "tcpFastOpen": "bool|int",
    "mark": INT,
    "tproxy": "enum:off|redirect|tproxy",
    "tcpMptcp": BOOL,
    "penetrate": BOOL,
    "domainStrategy": STR,
    "tcpMaxSeg": INT,
    "dialerProxy": STR,
    "tcpKeepAliveInterval": INT,
    "tcpKeepAliveIdle": INT,
    "tcpUserTimeout": INT,
    "tcpcongestion": "enum:bbr|cubic|reno",
    "V6Only": BOOL,
    "tcpWindowClamp": INT,
    "interface": STR,
    "trustedXForwardedFor": "list<str>",
    "addressPortStrategy": STR,
    "happyEyeballs": "opt:dict",
    "customSockopt": "list<dict>",
}

STREAM_SPEC: dict[str, Any] = {
    "network": "enum:tcp|kcp|ws|grpc|httpupgrade|xhttp|hysteria",
    "security": "enum:none|tls|reality|hysteria",
    "xhttpSettings": XHTTP_SPEC,
    "tlsSettings": TLS_SPEC,
    "realitySettings": REALITY_SPEC,
    "sockopt": SOCKOPT_SPEC,
    "externalProxy": "list<dict>",
    "finalmask": OPEN,
    "tcpSettings": OPEN,
    "kcpSettings": OPEN,
    "wsSettings": OPEN,
    "grpcSettings": OPEN,
    "httpupgradeSettings": OPEN,
    "hysteriaSettings": OPEN,
}

SNIFFING_SPEC: dict[str, Any] = {
    "enabled": BOOL,
    "destOverride": "list<str>",
    "metadataOnly": BOOL,
    "routeOnly": BOOL,
    "domains": "opt:list<str>",
}

VLESS_SETTINGS_SPEC: dict[str, Any] = {
    "clients": "list<dict>",
    "decryption": STR,
    "encryption": STR,
    "fallbacks": "list<dict>",
    "testseed": "opt:list<int>",
}

SHADOWSOCKS_SETTINGS_SPEC: dict[str, Any] = {
    "method": STR,
    "password": STR,
    "network": "enum:tcp|udp|tcp,udp",
    "clients": "list<dict>",
    "ivCheck": BOOL,
}

PROTOCOL_SETTINGS_SPEC: dict[str, dict[str, Any]] = {
    "vless": VLESS_SETTINGS_SPEC,
    "shadowsocks": SHADOWSOCKS_SETTINGS_SPEC,
}

INBOUND_SPEC: dict[str, Any] = {
    "listen": STR,
    "port": INT,
    "protocol": STR,
    "tag": STR,
    "settings": OPEN,
    "sniffing": SNIFFING_SPEC,
    "streamSettings": STREAM_SPEC,
    "allocate": OPEN,
}


def _kind_of(spec: str) -> str:
    body = spec.removeprefix("opt:")
    return body.split(":", 1)[0] if body.startswith("enum:") else body


def _check_value(value: Any, spec: Any, path: str, errors: list[str], warns: list[str]) -> None:
    if spec in (OPEN, "any"):
        return
    if isinstance(spec, dict):
        if not isinstance(value, dict):
            errors.append(f"{path}: ожидался объект, лежит {value!r}")
            return
        _walk_spec(value, spec, path, errors, warns)
        return

    kind = _kind_of(spec)
    if kind == "list<dict>":
        if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
            errors.append(f"{path}: ожидался список объектов, лежит {value!r}")
        return
    if kind == "list<str>":
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            errors.append(f"{path}: ожидался список строк, лежит {value!r}")
        return
    if kind == "list<int>":
        if not isinstance(value, list) or any(not isinstance(x, int) for x in value):
            errors.append(f"{path}: ожидался список чисел, лежит {value!r}")
        return

    if kind == "str" and not isinstance(value, str):
        errors.append(f"{path}: панель ждёт строку, лежит {type(value).__name__} {value!r}")
    elif kind == "int" and (not isinstance(value, int) or isinstance(value, bool)):
        errors.append(f"{path}: панель ждёт число, лежит {type(value).__name__} {value!r}")
    elif kind == "bool" and not isinstance(value, bool):
        errors.append(f"{path}: панель ждёт true/false, лежит {value!r}")
    elif kind == "dict" and not isinstance(value, dict):
        errors.append(f"{path}: панель ждёт объект, лежит {value!r}")
    elif kind == "list" and not isinstance(value, list):
        errors.append(f"{path}: панель ждёт список, лежит {value!r}")
    elif kind == "str|int" and not isinstance(value, (str, int)):
        errors.append(f"{path}: панель ждёт строку или число, лежит {value!r}")
    elif kind == "bool|int" and not isinstance(value, (bool, int)):
        errors.append(f"{path}: панель ждёт true/false или число, лежит {value!r}")

    if kind.startswith("enum:") and isinstance(value, str):
        allowed = kind[5:].split("|")
        if value not in allowed:
            errors.append(f"{path}: значение {value!r} вне списка панели {allowed}")


def _walk_spec(
    obj: dict[str, Any],
    spec: dict[str, Any],
    prefix: str,
    errors: list[str],
    warns: list[str],
) -> None:
    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        if key not in spec:
            warns.append(f"{path}: панель не знает такое поле и вырежет его при сохранении")
            continue
        _check_value(value, spec[key], path, errors, warns)


def validate_inbound(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warns: list[str] = []
    _walk_spec(config, INBOUND_SPEC, "", errors, warns)

    port = config.get("port")
    if isinstance(port, int) and not 1 <= port <= 65535:
        errors.append(f"port: {port} вне диапазона 1-65535")

    settings = config.get("settings")
    protocol = str(config.get("protocol", ""))
    if isinstance(settings, dict):
        spec = PROTOCOL_SETTINGS_SPEC.get(protocol)
        if spec is not None:
            _walk_spec(settings, spec, "settings", errors, warns)
        clients = settings.get("clients")
        if isinstance(clients, list):
            for index, client in enumerate(clients):
                if not isinstance(client, dict):
                    continue
                if protocol == "vless" and not str(client.get("id", "")):
                    errors.append(f"settings.clients[{index}].id: пустой id")
                if not str(client.get("email", "")):
                    warns.append(f"settings.clients[{index}].email: панель требует непустой email")

    stream = config.get("streamSettings")
    if not isinstance(stream, dict):
        return errors, warns

    xhttp = stream.get("xhttpSettings")
    if isinstance(xhttp, dict):
        if (
            xhttp.get("mode") in ("stream-up", "stream-one")
            and xhttp.get("uplinkHTTPMethod") == "GET"
        ):
            warns.append("xhttpSettings: uplinkHTTPMethod=GET имеет смысл только с mode=packet-up")
        xmux = xhttp.get("xmux")
        if isinstance(xmux, dict):
            concurrency = str(xmux.get("maxConcurrency", ""))
            connections = str(xmux.get("maxConnections", ""))
            if concurrency not in ("", "0") and connections not in ("", "0"):
                warns.append(
                    "xhttpSettings.xmux: maxConcurrency и maxConnections взаимоисключающие, "
                    "xray-core отклонит конфиг - оставь заполненным только одно из них"
                )

    tls = stream.get("tlsSettings")
    if isinstance(tls, dict):
        low, high = tls.get("minVersion"), tls.get("maxVersion")
        order = ["1.0", "1.1", "1.2", "1.3"]
        if low in order and high in order and order.index(low) > order.index(high):
            errors.append(f"tlsSettings: minVersion {low} выше maxVersion {high}")

    sniffing = config.get("sniffing")
    if isinstance(sniffing, dict) and "fakedns" in (sniffing.get("destOverride") or []):
        warns.append(
            "sniffing.destOverride содержит fakedns: без fakedns в настройках Xray "
            "панель игнорирует эту строку"
        )
    return errors, warns


# --- Плейсхолдеры ---
def is_placeholder(value: str) -> bool:
    stripped = value.strip()
    if not stripped or stripped == "REGENERATE PLS" or "(random)" in stripped:
        return True
    if HEX_PLACEHOLDER_RE.match(stripped):
        return True
    return any(mark in stripped for mark in DOMAIN_PLACEHOLDERS)


# --- Заполнение конфига ---
def fill_config(
    config: dict[str, Any],
    client_domain: str | None = None,
    server_domain: str | None = None,
) -> dict[str, Any]:
    protocol = str(config.get("protocol", ""))
    stream = config.get("streamSettings") or {}
    security = str(stream.get("security", ""))
    generated: dict[str, str] = {}

    if security == "reality":
        priv, pub = gen_reality_keypair()
        generated["reality_privateKey"] = priv
        generated["reality_publicKey"] = pub
        generated["reality_shortId"] = gen_short_id()

    if protocol == "vless":
        decryption, encryption, source = gen_vless_enc_pair()
        generated["vless_decryption"] = decryption
        generated["vless_encryption"] = encryption
        generated["vless_enc_source"] = source
    elif protocol == "trojan":
        password = gen_password()
        generated["client_password"] = password
        config.setdefault("settings", {})["password"] = password
    elif protocol == "shadowsocks":
        settings = config.setdefault("settings", {})
        password = gen_ss_password(str(settings.get("method", "")))
        generated["ss_password"] = password
        if is_placeholder(str(settings.get("password", ""))):
            settings["password"] = password

    def transform_string(value: str, key: str | None) -> str:
        if key == "decryption" and "(random)" in value:
            return generated.get("vless_decryption", value)
        if key == "encryption" and "(random)" in value:
            return generated.get("vless_encryption", value)
        if key in ("privateKey", "publicKey") and value == "REGENERATE PLS":
            return generated.get(f"reality_{key}", value)
        generated_hex = gen_hex_from_placeholder(value)
        if generated_hex is not None:
            generated.setdefault(f"{key or 'value'}_hex", generated_hex)
            return generated_hex
        if value == "REGENERATE PLS":
            password = gen_password()
            generated.setdefault(f"{key or 'value'}_password", password)
            return password
        if client_domain:
            value = value.replace("YOURDOMAIN.CLIENT.INHERE", client_domain)
        if server_domain:
            value = value.replace("YOURDOMAIN.SERVER.INHERE", server_domain)
        return value

    def walk(obj: Any, key: str | None = None) -> Any:
        if isinstance(obj, dict):
            return {k: walk(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            if key == "shortIds":
                if all(item == "REGENERATE PLS" for item in obj):
                    return [gen_short_id() for _ in range(8)]
                return [gen_short_id() if item == "REGENERATE PLS" else item for item in obj]
            return [walk(item, key) for item in obj]
        if isinstance(obj, str):
            return transform_string(obj, key)
        return obj

    return walk(config)


# --- Пакетный выбор ---
def parse_selection(text: str, count: int) -> list[int]:
    normalized = text.strip().lower()
    if normalized in ("all", "все", "всё", "*", "a", "в"):
        return list(range(1, count + 1))
    normalized = normalized.replace(",", " ").replace(";", " ").replace("\t", " ")
    selected: set[int] = set()
    for token in normalized.split():
        if "-" in token:
            parts = token.split("-")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                low, high = sorted((int(parts[0]), int(parts[1])))
                selected.update(i for i in range(low, high + 1) if 1 <= i <= count)
        elif token.isdigit():
            index = int(token)
            if 1 <= index <= count:
                selected.add(index)
    return sorted(selected)


_WL_CACHE: dict[Path, bool] = {}


def is_whitelist_quick(path: Path) -> bool:
    if path in _WL_CACHE:
        return _WL_CACHE[path]
    if "whitelist" in path.name.lower():
        _WL_CACHE[path] = True
        return True
    try:
        text = path.read_text(encoding="utf-8")
        result = any(mark in text for mark in DOMAIN_PLACEHOLDERS)
    except OSError:
        result = False
    _WL_CACHE[path] = result
    return result


def choose_configs(configs: list[Path]) -> list[Path]:
    print("\nДоступные конфиги:\n")
    for index, config_path in enumerate(configs, 1):
        mark = " [WL]" if is_whitelist_quick(config_path) else ""
        print(f"  {index:>2}. {config_path.stem}{mark}")
    print("\nВвод: номера через запятую/пробел, диапазоны (напр. '1,3,5-7'), или 'all'")
    while True:
        selected = parse_selection(input("Выбор: "), len(configs))
        if selected:
            return [configs[i - 1] for i in selected]
        print("Ничего не выбрано, попробуйте снова.")


def load_config(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as e:
        print(f"   [ОШИБКА] невалидный JSON: {e}")
        return None
    except OSError as e:
        print(f"   [ОШИБКА] файл не читается: {e}")
        return None
    if not isinstance(data, dict):
        print("   [ОШИБКА] верхний уровень JSON должен быть объектом")
        return None
    return data


def process_one(
    source: Path,
    out_dir: Path,
    client_domain: str | None,
    server_domain: str | None,
    force: bool,
) -> str:
    print(f"\n>>> {source.name}")
    config = load_config(source)
    if config is None:
        return "broken"

    protocol = str(config.get("protocol", ""))
    if protocol in SKIP_PROTOCOLS:
        print(f"   [ПРОПУСК] {protocol}")
        return "skipped"

    config = fill_config(config, client_domain, server_domain)

    errors, warn_lines = validate_inbound(config)
    for line in warn_lines:
        print(f"   {line}")
    for line in errors:
        print(f"   {line}")

    if errors and not force:
        return "invalid"

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / source.name
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print(f"   OK: {out_path}")
    return "invalid" if errors else "ok"


def collect_domains(
    paths: list[Path],
    args: argparse.Namespace,
) -> tuple[str | None, str | None]:
    if not any(is_whitelist_quick(path) for path in paths):
        return None, None
    client_domain = args.client_domain
    server_domain = args.server_domain
    if client_domain and server_domain:
        return client_domain, server_domain
    print("\nСреди выбранных есть WhiteList/CDN конфиги.")
    print("Домены будут применены ко всем WL-конфигам партии.")
    if not client_domain:
        client_domain = input("  Домен КЛИЕНТА (публичный): ").strip()
    if not server_domain:
        server_domain = input("  Домен СЕРВЕРА (на сервер): ").strip()
    return client_domain or None, server_domain or None


def run_batch(paths: list[Path], out_dir: Path, args: argparse.Namespace) -> dict[str, int]:
    client_domain, server_domain = collect_domains(paths, args)
    tally: dict[str, int] = {"ok": 0, "invalid": 0, "broken": 0, "skipped": 0}
    for path in paths:
        logger.info("Обработка: %s", path.name)
        tally[process_one(path, out_dir, client_domain, server_domain, args.force)] += 1
    return tally


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Генератор готовых inbound-конфигов для панели 3x-ui",
    )
    parser.add_argument("--list", action="store_true", help="показать список конфигов и выйти")
    parser.add_argument("--all", action="store_true", help="обработать все конфиги")
    parser.add_argument("--pick", help="номера/диапазоны, напр. '1,3,5-7'")
    parser.add_argument("--client-domain", help="домен клиента для WL-конфигов")
    parser.add_argument("--server-domain", help="домен сервера для WL-конфигов")
    parser.add_argument(
        "--out",
        type=Path,
        default=BUILD_DIR,
        help=f"папка результата (по умолчанию {BUILD_DIR})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="записывать конфиг даже если он не проходит схему панели",
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="спросить Enter в конце (для запуска двойным кликом)",
    )
    return parser


def resolve_targets(configs: list[Path], args: argparse.Namespace) -> list[Path] | None:
    if args.all:
        return configs
    if args.pick:
        indexes = parse_selection(args.pick, len(configs))
        if not indexes:
            print("[ОШИБКА] в --pick нет корректных номеров")
            return None
        return [configs[i - 1] for i in indexes]
    return None


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    logger.info("Запуск генератора конфигов")

    if not CONFIGS_DIR.exists():
        print(f"[ОШИБКА] папка '{CONFIGS_DIR}' не найдена")
        return 1
    configs = sorted(CONFIGS_DIR.glob("*.json"))
    if not configs:
        print(f"[ОШИБКА] в '{CONFIGS_DIR}' нет .json файлов")
        return 1

    if args.list:
        choose_configs(configs)
        return 0

    targets = resolve_targets(configs, args)
    total: dict[str, int] = {"ok": 0, "invalid": 0, "broken": 0, "skipped": 0}
    if targets is not None:
        for key, value in run_batch(targets, args.out, args).items():
            total[key] += value
    else:
        while True:
            for key, value in run_batch(choose_configs(configs), args.out, args).items():
                total[key] += value
            print("\nПакет обработан.")
            if input("\nЕщё партию? (y/n): ").strip().lower() not in (
                "y",
                "yes",
                "д",
                "да",
            ):
                break

    print(
        f"\nИтог: {total['ok']} записано, {total['invalid']} ошибки, {total['skipped']} пропущено, {total['broken']} битые"
    )
    if args.pause:
        input("\nEnter для выхода...")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nОтменено пользователем.")
    except Exception as e:  # noqa: BLE001
        print(f"\n[ОШИБКА] {e}")
        sys.exit(1)
