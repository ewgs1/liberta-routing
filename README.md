# Liberta Routing

Маршрут за пределы Матрицы. Собственные списки сервисов для Xray, sing-box и Remnawave.

**173 доменных правила, 13 категорий в этом тестовом изменении.** Общий список и отдельные категории собираются из реестра Liberta. В новых списках нет `category-ru`, `geoip:ru` и сторонних геобаз. URL ниже ведут на отдельно публикуемый канал `release`; состав сверяйте с его `manifest.json`.

[TXT](https://raw.githubusercontent.com/ewgs1/liberta-routing/release/liberta-direct.domains.txt) · [sing-box source](https://raw.githubusercontent.com/ewgs1/liberta-routing/release/liberta-direct.singbox.json) · [Правило Xray](https://raw.githubusercontent.com/ewgs1/liberta-routing/release/liberta-direct.xray.json) · [Все категории](https://github.com/ewgs1/liberta-routing/tree/release)

```sh
npm run build
npm run verify
```

[Подключение](docs/USAGE.md) · [Данные](docs/DATA.md) · [Разработка](docs/DEVELOPMENT.md) · [Совместимость](docs/COMPATIBILITY.md) · [MIT](LICENSE)

Сейчас тестируем. Прежний рабочий шаблон сохранён отдельно; полное покрытие приложений и работа на устройствах проверяются отдельно.
