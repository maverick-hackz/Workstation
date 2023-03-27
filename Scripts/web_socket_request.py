import base64
from websocket import create_connection


ws = create_connection("ws://62.173.140.174:16011/ws")
# decoded_data = base64.b64decode(ws.recv())
for i in range(0, 50):
    if i == 0:
        b64 = ws.recv().split(' ')[-1]
    else:
        b64 = ws.recv().split(' ')[-2]
    res = base64.b64decode(b64).decode()
    # print("Получен ответ:", b64, ">>>", res)
    req = eval(''.join(res.split(' ')[2:]))
    # print("Отправлен запрос:", req)
    ws.send(str(req))

print(ws.recv())

ws.close()
