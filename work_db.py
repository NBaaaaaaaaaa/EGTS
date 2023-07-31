class Packet_data:
    tid = oid = evid = tm = lat = long = spd = dir = alt = vld = bb = src = 0
    imei = coords = ''
    llsd = []

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
        self.lat = lat * 90 // 4294967295
        self.long = long * 180 // 4294967295

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

    def pr_all(self):
        print(self.tid, self.oid, self.evid, self.tm, self.lat, self.long, self.spd, self.dir, self.alt, self.vld, self.bb, self.src)
        print(self.imei, self.coords)
        print(self.llsd)

    def reset_llsd(self):
        self.llsd = []

    def gts_put(self):
        pass







