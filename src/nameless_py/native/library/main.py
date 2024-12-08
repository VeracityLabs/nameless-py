from nameless_py.native.library.server.monolithic import NativeMonolithicIssuer


def initialize_server(max_messages: int) -> bytes:
    issuer = NativeMonolithicIssuer(max_messages)
    return issuer.issuer.export_cbor()


# TODO: Implement Utilities For Users To Interpret The Server's Auxiliary Data
# IE: is the given accumulator a valid one? is one accumulator more recent than another?
