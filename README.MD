# Что это за проект?
*пусто*

# Что проект делает?
*пусто*

# Как установить проект?
*пусто*

# Как запустить проект?
## Шаг 1
В файле *config.py* изменить значения переменных.
```
host = ""
user = ""
password = ""
```

Эти значения рекомендуем оставить по умолчанию.
```
table_name = "egts_data"
db_name = "egts_db"
l_db_name = "local_egts_db"
```

Изменить значение частоты подключения к удаленной бд (в сек).
```
time_sleep = 0
```

Изменить путь к логам.
```
logs_path = "logger_files/logs"
```

## Шаг 2
Запустить файл *main_db/create_db.py*.

## Шаг 3
Запустить файл *local_db/create_db.py*.

## Шаг 4
Запустить файл *logger_files/logger.py*.

## Шаг 5
Запустить файл *egts.py*.


