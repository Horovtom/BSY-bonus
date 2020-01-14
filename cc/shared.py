serv_to_client = {
    "LS": "1.2.3.2",
    "W": "1.2.3.3",
    "PS": "1.2.3.5",
    "CAT": "1.2.3.6",
    "ACK": "1.2.3.4",
    "RST": "1.2.4.3",
    "NOP": "1.2.3.1",
    "SD": "1.2.2.2"
}
client_to_serv = {
    "HB": "google.com",
    "RESP": "ntppool.org",
    "DONE": "nordvpn.com"
}


def get_request_name(request_domain):
    for request, domain in client_to_serv.items():  # for name, age in dictionary.iteritems():  (for Python 2.x)
        if domain == request_domain:
            return request
    return request_domain
