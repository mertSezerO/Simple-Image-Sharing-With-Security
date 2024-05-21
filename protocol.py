import pickle


class SISP:
    ALLOWED_HEADER_TYPES = ["CONNECT", "DATA", "MESSAGE", "VERIFY"]

    def __init__(self):
        self.header = None
        self.body = None

    def set_header(self, header_type: str):
        if header_type not in self.ALLOWED_HEADER_TYPES:
            raise ValueError(
                f"Invalid header type: {header_type}. Allowed types are: {', '.join(self.ALLOWED_HEADER_TYPES)}"
            )
        self.header = header_type

    def set_body(self, **kwargs):
        self.body = Body(**kwargs)

    @staticmethod
    def serialize(packet):
        return pickle.dumps(packet)

    @staticmethod
    def deserialize(data):
        return pickle.loads(data)


class Body:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
