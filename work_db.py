from config import table_name
from datetime import datetime


class Packet_data:
    tid = oid = evid = tm = lat = long = spd = dir = alt = vld = bb = src = 0
    imei = coords = sensors = ''
    llsd = []

    cursor = db_connection = None

    def create_cursor(self, db_connection):
        self.db_connection = db_connection
        self.cursor = db_connection.cursor()

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

    def gts_put(self):
        # Если колво значений меньше 4, то заполняем -1.
        while len(self.llsd) < 4:
            self.llsd.append(-1)

        # пока так, надо потом будет удалить и добавить изменение этого значения.
        self.sensors = "12341qwerqwfdasf"

        try:
            insert_query = f'''
            INSERT INTO {table_name} 
              (imei, terminal_id, rec_id, event_id, time_recv, 
              time_event, lat, lon, coords_sign, speed, vector, height, is_valid, 
              is_blackbox, point_source, fuel_level_1, fuel_level_2, fuel_level_3, fuel_level_4, sensors) 
            VALUES 
              ('{self.imei}', {self.tid}, {self.oid}, {self.evid}, '{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}', 
              {self.tm}, {self.lat}, {self.long}, '{self.coords}', {self.spd}, {self.dir}, {self.alt}, {self.vld}, 
              {self.bb}, {self.src}, {self.llsd[0]}, {self.llsd[1]}, {self.llsd[2]}, {self.llsd[3]}, '{self.sensors}')
            '''

            self.cursor.execute(insert_query)
            self.db_connection.commit()

        except Exception as e:
            print(e)

