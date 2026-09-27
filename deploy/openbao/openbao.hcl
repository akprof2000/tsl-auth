# OpenBao — хранилище секретов проектов ТСЛ. Данные — файловое хранилище в томе, шифруются ключом хранилища
# (распечатывание при каждом старте). Слушает только внутреннюю сеть Docker; снаружи порт не публикуется.
# Для продуктива: TLS на листенере (tls_cert_file/tls_key_file) и распечатывание несколькими держателями ключей.
storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr      = "http://openbao:8200"
ui            = false
disable_mlock = true
