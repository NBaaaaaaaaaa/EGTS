import socket
from processing_result_codes import codes

sfrd_types = {
        "EGTS_PT_RESPONSE": 0,
        "EGTS_PT_APPDATA": 1,
        "EGTS_PT_SIGNED_APPDATA": 2
    }


def receive_data(port):
    # Создаем сокет для прослушивания порта
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', port))
    server_socket.listen(1)

    print("Сервер запущен и слушает порт {}...".format(port))

    # Принимаем входящее соединение
    connection, address = server_socket.accept()
    print("Установлено соединение с {}".format(address))

    try:
        while True:
            # Получаем данные от клиента
            data = connection.recv(1024)
            if not data:
                break

        print("Получены данные:", data)

    except KeyboardInterrupt:
        pass

    # Закрываем соединение и сокет
    connection.close()
    server_socket.close()


# Процедура вывода значений пакета.
def print_package_data(dict_data):
    text = f'''
    PRV (Protocol Version): {dict_data["PRV"]}
    SKID (Security Key ID): {dict_data["SKID"]}
    tmp_byte: {dict_data["tmp_byte"]}
    PRF (Prefix): {dict_data["PRF"]}
    RTE: {dict_data["RTE"]}
    ENA: {dict_data["ENA"]}
    CMP: {dict_data["CMP"]}
    PR: {dict_data["PR"]}
    HL (Header Length): {dict_data["HL"]}
    HE (Header Encoding): {dict_data["HE"]}
    FDL (Frame Data Length): {dict_data["FDL"]}
    PID (Packet Identifier): {dict_data["PID"]}
    PT (Packet Type): {dict_data["PT"]}
    PRA (Peer Address): {dict_data["PRA"]}
    RCA (Recipient Address): {dict_data["RCA"]}
    TTL (Time To Live): {dict_data["TTL"]}
    HCS (Header Check Sum): {dict_data["HCS"]}
    SFRD (Services Frame Data): {dict_data["SFRD"]}
    SFRCS (Services Frame Data Check Sum): {dict_data["SFRCS"]} 
    '''

    print(text)


# Функция преобразования данных пакета в словарь.
def dict_package_data(* data):
    dict_data = {
        "PRV": data[0],
        "SKID": data[1],
        "tmp_byte": data[2],
        "PRF": data[3],
        "RTE": data[4],
        "ENA": data[5],
        "CMP": data[6],
        "PR": data[7],
        "HL": data[8],
        "HE": data[9],
        "FDL": data[10],
        "PID": data[11],
        "PT": data[12],
        "PRA": data[13],
        "RCA": data[14],
        "TTL": data[15],
        "HCS": data[16],
        "SFRD": data[17],
        "SFRCS": data[18]
    }

    return dict_data


# Функция преобразования данных поля sfrd в словарь.
def dict_sfrd_data(* data):
    dict_data = {
        "RL": data[0],
        "RN": data[1],
        "RFL": data[2],
        "SSOD": data[3],
        "RSOD": data[4],
        "GRP": data[5],
        "RPP": data[6],
        "TMFE": data[7],
        "EVFE": data[8],
        "OBFE": data[9],
        "OID": data[10],
        "EVID": data[11],
        "TM": data[12],
        "SST": data[13],
        "RST": data[14],
        "RD": data[15]
    }

    return dict_data


# Функция перевода из 16 системы в 10.
def hex_to_dec(byte):
    if not byte:
        return None

    return int.from_bytes(byte, byteorder='big')


# Функция возвращает значение байта.
def param_byte(packet, count, reverse=True):
    param = packet[:count]
    packet = packet[count:]

    if count > 1 and reverse:
        param = param[::-1]

    return packet, param


# Функция получения битов из байта.
def param_bit(byte, cart):
    decimal_number = hex_to_dec(byte)
    binary_string = bin(decimal_number)[2:].zfill(sum(cart))
    packet = list(binary_string)
    tup = list()
    for i in cart:
        tup.append(''.join(packet[:i]))
        packet = packet[i:]
    return tup


# Функция получения данных пакета.
def get_package_data(packet):
    prv = skid = tmp_byte = prf = rte = ena = cmp = pr = hl = he = \
        fdl = pid = pt = pra = rca = ttl = hcs = sfrd = sfrcs = 0x00

    while len(packet) > 0:
        try:
            packet, prv = param_byte(packet, 1, False)
            packet, skid = param_byte(packet, 1, False)
            packet, tmp_byte = param_byte(packet, 1, False)

            prf, rte, ena, cmp, pr = param_bit(tmp_byte, (2, 1, 2, 1, 2))

            packet, hl = param_byte(packet, 1, False)
            packet, he = param_byte(packet, 1, False)
            packet, fdl = param_byte(packet, 2, True)
            packet, pid = param_byte(packet, 2, True)
            packet, pt = param_byte(packet, 1, False)

            if int(rte) == 1:
                packet, pra = param_byte(packet, 2, True)
                packet, rca = param_byte(packet, 2, True)
                packet, ttl = param_byte(packet, 1, False)

            packet, hcs = param_byte(packet, 1, False)
            packet, sfrd = param_byte(packet, hex_to_dec(fdl), False)
            packet, sfrcs = param_byte(packet, 2, True)

            dict_data = dict_package_data(prv, skid, tmp_byte, prf, rte, ena, cmp, pr, hl, he,
                                          fdl, pid, pt, pra, rca, ttl, hcs, sfrd, sfrcs)
            print_package_data(dict_data)

            return dict_data

        except Exception as e:
            print(e)
            return None


# Функция вычисления контрольной суммы crc8.
def crc8(data):
    crc = 0xFF
    polynomial = 0x31  # Полином для CRC-8 (CRC-8-ATM)

    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ polynomial
            else:
                crc <<= 1
            crc &= 0xFF

    return crc.to_bytes(1, byteorder='big')


# Функция вычисления контрольной суммы crc16.
def crc16(data):
    crc = 0xFFFF
    polynomial = 0x1021  # Полином для CRC-16 (CRC-16-IBM)

    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ polynomial
            else:
                crc <<= 1
            crc &= 0xFFFF

    return crc.to_bytes(2, byteorder='big')


# Функция создания поля SFRD и SFRCS для подтверждения пакета Транспортного Уровня.
def create_EGTS_PT_RESPONSE(rpid, pr):
    rpid = rpid[::-1]
    pr = pr.to_bytes(1, byteorder='big')

    return rpid + pr + crc16(rpid + pr)[::-1]
    # Структуры  SDR 1, ... не добавил. Хз надо или нет.


# Функция обработки поля SFRD для подтверждения пакета Транспортного Уровня.
def processing_EGTS_PT_RESPONSE(byte_string):
    # А это вообще не надо вроде. А не. При отправке на другую ТП надо будет сформировать пакет TTL-1 hcs перерасчет
    pass


# Функция обработки поля SFRD для пакета содержащего данные ППУ.
def processing_EGTS_PT_APPDATA(byte_string, dict_data_sfrd=None):
    if not dict_data_sfrd:
        dict_data_sfrd = {}

    dict_data_sfrd["SFRD"] = {}

    rl = rn = rfl = ssod = rsod = grp = rpp = tmfe = evfe = obfe = oid = evid = tm = sst = rst = st = 0x00
    srt = srl = srd = 0x00
    i = 0
    while len(byte_string) > 0:
        try:
            byte_string, rl = param_byte(byte_string, 2, True)
            byte_string, rn = param_byte(byte_string, 2, True)
            byte_string, rfl = param_byte(byte_string, 1, False)

            ssod, rsod, grp, rpp, tmfe, evfe, obfe = param_bit(rfl, (1, 1, 1, 2, 1, 1, 1))

            if int(obfe) == 1:
                byte_string, oid = param_byte(byte_string, 4, True)

            if int(evfe) == 1:
                byte_string, evid = param_byte(byte_string, 4, True)

            if int(tmfe) == 1:
                byte_string, tm = param_byte(byte_string, 4, True)

            byte_string, sst = param_byte(byte_string, 1, False)
            byte_string, rst = param_byte(byte_string, 1, False)
            byte_string, rd = param_byte(byte_string, hex_to_dec(rl), False)

            dict_srd = {}
            j = 0
            # Разложение данных записи на подзаписи.
            while len(rd) > 0:
                rd, srt = param_byte(rd, 1, False)
                rd, srl = param_byte(rd, 2, True)
                rd, srd = param_byte(rd, hex_to_dec(srl), False)

                j += 1
                dict_srd[f"SRD={j}"] = {"SRT": srt, "SRL": srl, "SRD": srd}

            dict_data = dict_sfrd_data(rl, rn, rfl, ssod, rsod, grp, rpp, tmfe,
                                       evfe, obfe, oid, evid, tm, sst, rst, dict_srd)
            i += 1
            dict_data_sfrd["SFRD"][f"RID={i}"] = dict_data

        except Exception as e:
            print(e)
            return None

    print(f"EGTS_PT_APPDATA обработан {dict_data_sfrd}")
    return dict_data_sfrd


# Функция обработки поля SFRD для пакета содержащего данные ППУ с цифровой подписью.
def processing_EGTS_PT_SIGNED_APPDATA(byte_string):
    dict_data_sfrd = {}
    byte_string, dict_data_sfrd["SIGL"] = param_byte(byte_string, 2, True)

    if hex_to_dec(dict_data_sfrd["SIGL"]) > 0:
        byte_string, dict_data_sfrd["SIGD"] = param_byte(byte_string, hex_to_dec(dict_data_sfrd["SIGL"]), False)

    dict_data_sfrd.update(processing_EGTS_PT_APPDATA(byte_string, dict_data_sfrd))

    # return dict_data_sfrd
    print(f"EGTS_PT_SIGNED_APPDATA обработан {dict_data_sfrd}")


# Функция создания ответного пакета. Пока None второй аргумент, позже будет нужен.
def create_response_package(dict_data, package_type, code=None):
    send_package = b''

    for param in list(dict_data.keys())[:-2]:
        if int(dict_data["RTE"]) == 1 and (param in ("PRA", "RCA", "TTL")):
            send_package += dict_data[param]

        elif param in ("PRF", "RTE", "ENA", "CMP", "PR") or \
                int(dict_data["RTE"]) == 0 and (param in ("PRA", "RCA", "TTL")):
            pass

        else:
            if param in ("FDL", "PID"):
                send_package += dict_data[param][::-1]

            else:
                send_package += dict_data[param]

    if package_type == sfrd_types["EGTS_PT_RESPONSE"]:
        #  EGTS_PT_RESPONSE (подтверждение на пакет транспортного уровня);
        send_package += create_EGTS_PT_RESPONSE(dict_data["PID"], code)

    elif package_type in (sfrd_types["EGTS_PT_APPDATA"], sfrd_types["EGTS_PT_SIGNED_APPDATA"]):
        # EGTS_PT_APPDATA (пакет, содержащий данные протокола уровня поддержки услуг);
        # EGTS_PT_SIGNED_APPDATA (пакет, содержащий данные протокола уровня поддержки услуг с цифровой подписью).
        send_package += dict_data["SFRD"] + dict_data["SFRCS"][::-1]

    # return send_package
    print(f"Пакет на отправку: {send_package}")


# Функция обработки данных пакета.
def package_data_processing(packet):
    dict_data = get_package_data(packet)

    if dict_data:
        # Поддерживаются ли версии PRV, PRF.
        if dict_data["PRV"] == b'\x01' and dict_data["PRF"] == '00':
            # Проверка длины заголовка.
            if hex_to_dec(dict_data["HL"]) in range(11, 17):

                data_checksum_crc8 = list(packet[:hex_to_dec(dict_data["HL"]) - 1])
                checksum_crc8 = crc8(data_checksum_crc8)
                # Проверка контрольной суммы заголовка.
                if checksum_crc8 == dict_data["HCS"]:
                    # Необходимость дальнейшей маршрутизации.
                    if dict_data["RTE"] == '0':
                        # Есть ли информация уровня поддержки услуг.
                        if hex_to_dec(dict_data["FDL"]) > 0:

                            data_checksum_crc16 = list(dict_data["SFRD"])
                            checksum_crc16 = crc16(data_checksum_crc16)
                            # Проверка контрольной суммы информация уровня поддержки услуг.
                            if checksum_crc16 == dict_data["SFRCS"]:
                                # Проверка кода алгоритма шифрования.
                                if dict_data["ENA"] == '00':
                                    create_response_package(dict_data, sfrd_types["EGTS_PT_RESPONSE"],
                                                            codes["EGTS_PC_OK"])

                                    package_type = hex_to_dec(dict_data["PT"])
                                    # Обрабатываем информацию уровня поддержки в зависимости от значения PT.
                                    if package_type == sfrd_types["EGTS_PT_RESPONSE"]:
                                        print("EGTS_PT_RESPONSE")
                                        #  EGTS_PT_RESPONSE (подтверждение на пакет транспортного уровня);
                                        # хз надо или нет, но кода я участвую в цепи пересылок пакета, то будто бы надо
                                        # я получу ответ от пересылки, и ответ направлю, кто мне скинул пакет
                                        pass

                                    elif package_type == sfrd_types["EGTS_PT_APPDATA"]:
                                        # EGTS_PT_APPDATA (пакет, содержащий данные протокола уровня поддержки услуг);
                                        processing_EGTS_PT_APPDATA(dict_data["SFRD"])

                                    elif package_type == sfrd_types["EGTS_PT_SIGNED_APPDATA"]:
                                        # EGTS_PT_SIGNED_APPDATA (пакет, содержащий данные протокола уровня поддержки услуг с цифровой подписью).
                                        processing_EGTS_PT_SIGNED_APPDATA(dict_data["SFRD"])

                                else:
                                    create_response_package(dict_data, sfrd_types["EGTS_PT_RESPONSE"],
                                                            codes["EGTS_PC_DECRYPT_ERROR"])

                            else:
                                create_response_package(dict_data, sfrd_types["EGTS_PT_RESPONSE"],
                                                        codes["EGTS_PC_DATACRC_ERROR"])

                        else:
                            create_response_package(dict_data, sfrd_types["EGTS_PT_RESPONSE"],
                                                    codes["EGTS_PC_OK"])

                    else:

                        if hex_to_dec(dict_data["TTL"]) > 0:
                            dict_data["TTL"] = (hex_to_dec(dict_data["TTL"]) - 1).to_bytes(1, byteorder='big')
                            data_checksum_crc8 = list(packet[:hex_to_dec(dict_data["HL"]) - 2]).append(dict_data["TTL"])
                            dict_data["HCS"] = crc8(data_checksum_crc8)

                            # Создаем пакет для отправки на другую ТП.
                            create_response_package(dict_data, hex_to_dec(dict_data["PT"]))

                        else:
                            create_response_package(dict_data, sfrd_types["EGTS_PT_RESPONSE"],
                                                    codes["EGTS_PC_TTLEXPIRED"])

                else:
                    create_response_package(dict_data, sfrd_types["EGTS_PT_RESPONSE"],
                                            codes["EGTS_PC_HEADERCRC_ERROR"])

            else:
                create_response_package(dict_data, sfrd_types["EGTS_PT_RESPONSE"],
                                        codes["EGTS_PC_INC_HEADERPORM"])

        else:
            create_response_package(dict_data, sfrd_types["EGTS_PT_RESPONSE"],
                                    codes["EGTS_PC_UNC_PROTOCOL"])


if __name__ == "__main__":
    # receive_data(1338)
    a = [
        b'\x01\x00\x00\x0b\x00$\x00\x01\x00\x01\x84\x19\x00\x01\x00\x81\x00\x00\x00\x00\x01\x01\x01\x16\x00\x00\x00\x00\x00B868345032085953\xf5\x03\xf9\xce',
        b'\x01\x00\x00\x0b\x00$\x00\x02\x00\x01N\x19\x00\x02\x00\x81\x00\x00\x00\x00\x01\x01\x01\x16\x00\x00\x00\x00\x00B868345032085953\xf5\x03\xb7z',
        b'\x01\x00\x00\x0b\x00$\x00\x03\x00\x01\x08\x19\x00\x03\x00\x81\x00\x00\x00\x00\x01\x01\x01\x16\x00\x00\x00\x00\x00B868345032085953\xf5\x03\x92\xe6',
        b'\x01\x00\x00\x0b\x00$\x00\x04\x00\x01\xeb\x19\x00\x04\x00\x81\x00\x00\x00\x00\x01\x01\x01\x16\x00\x00\x00\x00\x00B868345032085953\xf5\x03\n\x02'
    ]

    package_data_processing(a[1])
