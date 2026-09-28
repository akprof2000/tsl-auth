#!/bin/sh
# Защита конвейера от «зелёного нуля»: dotnet test --no-build без собранных бинарников или без найденных тестов
# завершается с кодом 0 и пустым выводом. Скрипт читает <Counters> из .trx и требует: тесты выполнены (executed > 0)
# и ни один не упал. Использование: scripts/ci-check-trx.sh TestResults/unit.trx [минимум выполненных тестов]
set -eu
trx="$1"; min="${2:-1}"
[ -f "$trx" ] || { echo "::error::Файл результатов $trx не создан — тесты не запускались"; exit 1; }
counters=$(grep -o '<Counters [^>]*' "$trx" | head -1)
num() { echo "$counters" | grep -o " $1=\"[0-9]*\"" | grep -o '[0-9]*'; }
executed=$(num executed); failed=$(num failed); errors=$(num error); total=$(num total)
echo "Тесты: всего $total, выполнено $executed, упало $failed, ошибок $errors"
[ "${executed:-0}" -ge "$min" ] || { echo "::error::Выполнено $executed тестов, ожидалось не меньше $min"; exit 1; }
[ "${failed:-0}" -eq 0 ] && [ "${errors:-0}" -eq 0 ] || { echo "::error::Есть упавшие тесты"; exit 1; }
