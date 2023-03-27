def encode():
    while True:
        enter_encode = str(input("Enter text: "))
        enc_hex = '\\'.join(hex(ord(i))[1:] for i in enter_encode)
        print("HEX\t\t\t==>\t\t"'\\{0}'.format(enc_hex))


encode()
