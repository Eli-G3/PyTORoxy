import binascii
import os
import connect

RELAYIP = '10.0.0.28'
ORPORT = 9150
MAX_RESPONSE_LEN = 2048
ZERO = '00'
RANDOM_LEN = 20
random_X = str(binascii.hexlify(os.urandom(RANDOM_LEN)))
REQUEST = b'0000070006000300040005'
# REQUEST = ('0000' + '07' + '0002' + '0004' +
#            '00000000' + '08' + '00000000' + '04' + '04' + '00000000' + '00' +
#            ZERO * 498 +
#            '80000000' + '05' + random_X +
#            ZERO * 489)

print('SSL Server: {}:{}'.format(RELAYIP, ORPORT))
print(REQUEST)
response = connect.tls_request(RELAYIP, ORPORT, binascii.unhexlify(REQUEST),
                       MAX_RESPONSE_LEN)
print(binascii.hexlify(response))