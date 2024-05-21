import pickle


class SISPPacket:
    def __init__(self, header):
        self.header = header

    def set_body(self, **kwargs):
        self.body = Body(**kwargs)


class Body:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class SISP:

    @staticmethod
    def create_connection_packet() -> SISPPacket:
        return SISPPacket("CONNECT")

    @staticmethod
    def create_data_packet() -> SISPPacket:
        return SISPPacket("DATA")

    @staticmethod
    def create_message_packet() -> SISPPacket:
        return SISPPacket("MESSAGE")

    @staticmethod
    def serialize(packet: SISPPacket) -> bytes:
        return pickle.dumps(packet)

    @staticmethod
    def deserialize(data: bytes) -> SISPPacket:
        return pickle.loads(data)
