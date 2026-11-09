#!/usr/bin/env python3
"""FIM - простой контроль целостности файлов (SHA-256 + HMAC)."""
import argparse, hashlib, hmac, json, os, sys
from getpass import getpass

DB = "baseline.json"                                  # файл эталона
EXCLUDE = {".git", "__pycache__", DB}                 # что пропускаем


def file_hash(path):
    """SHA-256 одного файла."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def scan(folder):
    """Обходит папку, возвращает {путь: хэш}."""
    result = {}
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in EXCLUDE]       # пропускаем папки
        for name in files:
            if name not in EXCLUDE:
                path = os.path.join(root, name)
                result[path] = file_hash(path)
    return result


def sign(files, key):
    """HMAC-подпись базы: без ключа её не подделать."""
    text = json.dumps(files, sort_keys=True).encode()
    return hmac.new(key.encode(), text, hashlib.sha256).hexdigest()


def init(folder):
    key = getpass("Секретный ключ: ")
    files = scan(folder)
    with open(DB, "w") as f:
        json.dump({"folder": folder, "files": files, "hmac": sign(files, key)}, f, indent=2)
    print(f"Эталон создан: {len(files)} файлов")


def check():
    key = getpass("Секретный ключ: ")
    with open(DB) as f:
        db = json.load(f)

    # 1. Проверяем, что сама база не подменена
    if not hmac.compare_digest(sign(db["files"], key), db["hmac"]):
        print("!!! ЭТАЛОН ПОДДЕЛАН (подпись не совпала) !!!")
        sys.exit(2)

    # 2. Сравниваем старое и новое состояние
    old, new = db["files"], scan(db["folder"])
    for path in new:
        if path not in old:
            print("NEW      ", path)
        elif new[path] != old[path]:
            print("MODIFIED ", path)
    for path in old:
        if path not in new:
            print("DELETED  ", path)
    if old == new:
        print("Изменений нет")


parser = argparse.ArgumentParser()
parser.add_argument("command", choices=["init", "check"])
parser.add_argument("folder", nargs="?", help="папка (только для init)")
args = parser.parse_args()

if args.command == "init":
    init(args.folder)
else:
    check()
