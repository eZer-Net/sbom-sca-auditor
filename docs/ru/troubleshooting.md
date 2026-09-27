# Решение проблем

## Не удалось получить dependency graph

Когда требуется resolved graph, scanner использует штатные package/build инструменты обнаруженной экосистемы. Если resolution завершается ошибкой, scanner не придумывает транзитивные версии. В зависимости от ecosystem он либо использует детерминированную локальную metadata, либо сохраняет module/dependencies в `unresolved.json`.

Высокоуровневая причина сохраняется в `logs/process.json`.

## Gradle или Maven выполняют project logic

Build systems могут выполнять plugins/scripts самого проекта. Недоверенные repositories сканируйте через Docker или изолированный CI worker.

## C/C++ source остаётся unresolved

Один `#include` не определяет уникальный package/version. Для resolved C/C++ graph используйте поддерживаемый `conanfile.py`, `conanfile.txt` или `vcpkg.json`.

## Private registries

Scanner не пытается незаметно аутентифицироваться в произвольные private registries. Package/build инструменты используют обычную конфигурацию окружения; отсутствие credentials приводит к ошибке resolution, а не к выдуманным данным.
