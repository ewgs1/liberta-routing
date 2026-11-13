# Liberta Routing

Маршрут за пределы Матрицы. Правила маршрутизации для Xray, sing-box и Remnawave.

**111 доменов, 13 классов, 45 явных direct-записей**, прежние маршруты и DNS.

[Конфигурация Xray / Remnawave](dist/smart.xray.json) · [Явные домены для sing-box](dist/smart.singbox.json) · [TXT](dist/smart.domains.txt)

```sh
npm run verify
```

sing-box и TXT экспортируют 45 явных доменных правил; широкие географические правила исходного Xray-профиля в них не входят.

[Аудит](docs/AUDIT.md) · [Подключение](docs/INTEGRATION.md) · [MIT](LICENSE)
