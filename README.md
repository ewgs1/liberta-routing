# Liberta Routing

Свой маршрут за пределы Матрицы. Правила маршрутизации для Xray, sing-box и Remnawave.

**v1 — тестовая версия.** Сейчас проверяем небольшой собственный набор из 8 точных хостов: они идут напрямую, остальной трафик — через VPN. У записей есть официальные источники и даты проверки. Работу сервисов из России ещё нужно проверить.

Файлы: [Xray JSON](releases/v1/smart.xray.json) · [sing-box source JSON](releases/v1/smart.singbox.json) · [TXT](releases/v1/smart.domains.txt).

```sh
npm run verify
```

Smart v5 сохранён отдельно; его повторная сборка совпадает с исходной побайтово. Этот набор его автоматически не заменяет.

[Подключение и тестовый профиль](docs/INTEGRATION.md) · [Аудит](docs/AUDIT.md) · [MIT](LICENSE)
