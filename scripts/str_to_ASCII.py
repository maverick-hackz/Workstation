while (s:=input('Enter text:\n')).lower() != 'exit':
    print('\nASCII text: ')
    for i in range(len(s) - 1):
        print(ord(s[i]), end = ',')
    print(ord(s[-1]),'\n\n')
