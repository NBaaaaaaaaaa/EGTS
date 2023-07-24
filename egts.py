import socket


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
        "tmp_byte":  data[2],
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
    prv = skid = prf = rte = ena = cmp = pr = hl = he = fdl = pid = pt = pra = rca = ttl = hcs = sfrd = sfrcs = 0x00

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
            packet, sfrcs = param_byte(packet, 2, True)         #пометка. почему то нет контрольной суммы у информации sfrd

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


# Функция создания ответного пакета. Пока None второй аргумент, позже будет нужен.
def create_response_package(dict_data, sfrd_type=None):
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

    # Тут еще не добавлены последнии два поля.
    return send_package


# Функция обработки данных пакета.
def package_data_processing(packet):
    dict_data = get_package_data(packet)

    if dict_data:

        if dict_data["PRV"] == b'\x01' and dict_data["PRF"] == '00':

            if hex_to_dec(dict_data["HL"]) in (11, 16):

                data_to_checksum = list(packet[:hex_to_dec(dict_data["HL"]) - 1])
                checksum = crc8(data_to_checksum)

                if checksum == dict_data["HCS"]:

                    # Добавить в условие проверку адресa текущей тп dict_data["RCA"]
                    if dict_data["RTE"] == '0':

                        if hex_to_dec(dict_data["FDL"]) > 0:

                            data_to_checksum = list(dict_data["SFRD"])
                            checksum = crc16(data_to_checksum)

                            if checksum == dict_data["SFRCS"]:

                                if dict_data["ENA"] == '00':
                                    # Декодирование прошло успешно?

                                    # Если данные не были сжаты в поле SFRD
                                    if dict_data["CMP"] == '0':
                                        # Распаковка данных
                                        # match hex_to_dec(dict_data["PT"]):
                                        #     case (sfrd_types[]):
                                        #         #  EGTS_PT_RESPONSE (подтверждение на пакет транспортного уровня);
                                        #         pass
                                        #     case (sfrd_types[]):
                                        #         # EGTS_PT_APPDATA (пакет, содержащий данные протокола уровня поддержки услуг);
                                        #
                                        #         pass
                                        #     case (sfrd_types[]):
                                        #         # EGTS_PT_SIGNED_APPDATA (пакет, содержащий данные протокола уровня поддержки услуг с цифровой подписью).
                                        #         pass

                                        # Я думаю это надо вынести в отдельные метод, что дальше будует.
                                        # Данные уровня поддерржки
                                        # Отправить EGTS_PC_OK
                                        pass

                                    # Если данные были сжаты.
                                    else:
                                        # Распаковка данных
                                        # распаковка успешно прошшла?
                                        pass


                                else:
                                    # ENA поддерживается?
                                    pass

                            else:
                                # отправить код EGTS_PC_DATACRC_ERROR
                                pass


                        else:
                            # Код EGTS_PC_OK
                            pass

                    else:
                        #
                        #     if hex_to_dec(dict_data["TTL"]) > 0:
                        #         dict_data["TTL"] = (hex_to_dec(dict_data["TTL"]) - 1).to_bytes(1, byteorder='big')
                        #         произвести перерасчет HCS
                        #         data_to_checksum = list(packet[:hex_to_dec(dict_data["HL"]) - 2]).append(dict_data["TTL"])
                        #         checksum = crc8(data_to_checksum)
                        #         отпрвить на другую ТП
                        #
                        #     else:
                        #         Отправить код EGTS_PC_TTLEXPIRED

                        pass

                else:
                    # Тут надо отправить код EGTS_PC_HEADERCRC_ERROR
                    pass

            else:
                # Тут надо отправить код EGTS_PC_INC_HEADERPORM
                pass

        else:
            # Тут надо отправить код EGTS_PC_UNC_PROTOCOL
            pass


sfrd_types = {
        "EGTS_PT_RESPONSE": 0,
        "EGTS_PT_APPDATA": 1,
        "EGTS_PT_SIGNED_APPDATA": 2
    }

if __name__ == "__main__":
    # receive_data(1337)
    a = [
        b'\x01\x00\x00\x0b\x00$\x00\x01\x00\x01\x84\x19\x00\x01\x00\x81\x00\x00\x00\x00\x01\x01\x01\x16\x00\x00\x00\x00\x00B868345032085953\xf5\x03\xf9\xce',
        b'\x01\x00\x00\x0b\x00$\x00\x02\x00\x01N\x19\x00\x02\x00\x81\x00\x00\x00\x00\x01\x01\x01\x16\x00\x00\x00\x00\x00B868345032085953\xf5\x03\xb7z',
        b'\x01\x00\x00\x0b\x00$\x00\x03\x00\x01\x08\x19\x00\x03\x00\x81\x00\x00\x00\x00\x01\x01\x01\x16\x00\x00\x00\x00\x00B868345032085953\xf5\x03\x92\xe6',
        b'\x01\x00\x00\x0b\x00$\x00\x04\x00\x01\xeb\x19\x00\x04\x00\x81\x00\x00\x00\x00\x01\x01\x01\x16\x00\x00\x00\x00\x00B868345032085953\xf5\x03\n\x02'
    ]

    package_data_processing(a[0])
