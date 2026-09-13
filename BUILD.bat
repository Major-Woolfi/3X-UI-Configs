@echo off
chcp 65001 >nul
title XRay Config Generator
set PYTHONIOENCODING=utf-8

cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ОШИБКА] Python не найден в PATH.
    echo Установите Python 3.9+ с сайта https://www.python.org/downloads/
    echo При установке ОБЯЗАТЕЛЬНО поставьте галочку "Add Python to PATH".
    pause
    exit /b 1
)

echo [INFO] Проверка зависимостей...
python Scripts\install.py
if errorlevel 1 (
    echo [ОШИБКА] Не удалось установить зависимости.
    pause
    exit /b 1
)

python Scripts\generate_config.py --pause
if errorlevel 1 (
    echo [ОШИБКА] Генератор завершился с ошибкой.
    pause
)