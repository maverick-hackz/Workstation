while (s:=input()).lower() != 'exit':
    for i in range(len(s)):
        print(ord(s[i]), end = ',')
    print('\n')
