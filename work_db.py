import time

import mysql.connector
import sqlite3

from datetime import datetime

from main_db.m_config import host, user, password, db_name, table_name
from local_db.l_config import l_db_name, table_name  # Можно не импортировать table_name, так как они одинаковы.

from logger_files.type_text import Types_text
from logger_files.logger import Logging

from threading import Thread


# Функция подключения к локальной бд.
def connect_local_db():
    # Подключение к существующей базе данных или создание новой, если её нет.
    connection = sqlite3.connect(f'local_db/{l_db_name}.db', check_same_thread=False)
    return connection


# Функция подключения к основной бд.
def connect_main_db():
    try:
        # Подключаемся к бд.
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=db_name
        )

        return {"main": True, "connection": connection}

    except Exception as e:
        print(e)
        Logging("").logging(fromm=2, to=3, type_text=Types_text.ERROR.value,
                            text=f"Ошибка подключения к серверу с бд. {e}")
        return {"main": False, "connection": connect_local_db()}


def create_cursor(db_connection):
    Packet_data.is_main = db_connection["main"]
    Packet_data.db_connection = db_connection["connection"]
    Packet_data.cursor = Packet_data.db_connection.cursor()


# Процедура проверки доступа к серверу с бд.
def check_connect(always):
    while True:
        # Создаем подключение к бд.
        create_cursor(connect_main_db())

        if not always:
            break

        time.sleep(5)


# Процедура создания потока проверки доступа к серверу с бд.
def create_check_connect():
    # Создаем новый поток для обработки данных клиента
    t = Thread(target=check_connect, daemon=True, args=(True, ))
    t.start()


class Packet_data:
    tid = oid = evid = tm = lat = long = spd = dir = alt = vld = bb = src = 0
    imei = coords = sensors = ''
    llsd = []

    # Статические переменные.
    is_main = db_connection = cursor = in_local = None

    def update_auth(self, tid, imei):
        self.tid = tid
        self.imei = imei

    def set_oid(self, oid):
        self.oid = oid

    def set_evid(self, evid):
        self.evid = evid

    def set_tm(self, tm):
        self.tm = tm

    def update_pos_data(self, lat, long, lohs, lahs, bb, vld, spd, dir, src, alt):
        self.lat = round(lat * 90 / 4294967295, 3)
        self.long = round(long * 180 / 4294967295, 3)

        if lahs and lohs:
            self.coords = 'SE'

        elif lahs:
            self.coords = 'SW'

        elif lohs:
            self.coords = 'NE'

        else:
            self.coords = 'NW'

        self.bb = bb
        self.vld = vld
        self.spd = spd
        self.dir = dir
        self.src = src
        self.alt = alt

    def update_llsd(self, llsd):
        self.llsd.append(llsd)

    def reset_llsd(self):
        self.llsd = []

    def insert_data(self, data=None):
        try:
            type_placeholder = {
                True: "%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s",
                False: "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?"
            }

            insert_query = f'''
            INSERT INTO {table_name} 
              (imei, terminal_id, rec_id, event_id, time_recv, 
              time_event, lat, lon, coords_sign, speed, vector, height, is_valid, 
              is_blackbox, point_source, fuel_level_1, fuel_level_2, fuel_level_3, fuel_level_4, sensors) 
            VALUES ({type_placeholder[Packet_data.is_main]})
            '''

            if not data:
                insert_data = (self.imei, self.tid, self.oid, self.evid, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                               self.tm, self.lat, self.long, self.coords, self.spd, self.dir, self.alt, self.vld,
                               self.bb, self.src, self.llsd[0], self.llsd[1], self.llsd[2], self.llsd[3], self.sensors)
            else:
                insert_data = data

            Packet_data.cursor.execute(insert_query, insert_data)
            Packet_data.db_connection.commit()

            return True

        except Exception as e:
            print(e)
            # Packet_data.cursor.close()
            # Packet_data.db_connection.close()
            return False

    def gts_put(self):
        # Если колво значений меньше 4, то заполняем -1.
        while len(self.llsd) < 4:
            self.llsd.append(-1)

        # пока так, надо потом будет удалить и добавить изменение этого значения.
        self.sensors = "12341qwerqwfdasf"

        # Запись в основную бд.
        if Packet_data.is_main:
            main_connect = True
            # Если соединение было разорвано.
            if not self.insert_data():
                create_cursor({"main": False, "connection": connect_local_db()})
                print("11111111111111111")
                self.insert_data()
                print("222222222222222222")
                main_connect = False

            if main_connect:
                # Если были записаны данные в локальную бд.
                if Packet_data.in_local and Packet_data.is_main:
                    local_connection = connect_local_db()
                    local_cursor = local_connection.cursor()

                    local_cursor.execute(f'SELECT * FROM {table_name}')

                    # Получение всех строк результата в виде списка кортежей.
                    rows = local_cursor.fetchall()

                    # Запись всех строк из локальной бд в основную.
                    for row in [list(row) for row in rows]:
                        # Если записалось в основную бд.
                        if self.insert_data(row[1:]):
                            # Удаляем запись из локальной бд.
                            local_cursor.execute(f'DELETE FROM {table_name} WHERE id = {row[0]}')
                            local_connection.commit()

                    local_cursor.execute(f'SELECT * FROM {table_name}')
                    if len(local_cursor.fetchall()) > 0:
                        Packet_data.in_local = False

                    # Закрываем соединение с локальной бд.
                    local_cursor.close()
                    local_connection.close()

        # Запись в локальную бд.
        else:
            print("3333333333333333333333333")
            self.insert_data()
            Packet_data.in_local = True
