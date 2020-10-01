import requests
import hashlib
import sys

def filterbyvalue(seq, value):
   '''
   Finds hash tail in url responce text
   :param seq:
   :param value:
   :return:
   '''
   for el in seq:
       if el[0]==value:
           yield el[1]

def request_api_data(part_hash):
    '''
    Requests hashes tails from url
    :param part_hash: str - first 5 characters of hash
    :return: responce - url responce object
    '''

    url = 'https://api.pwnedpasswords.com/range/' + part_hash
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error resolving adress {url}')
    return res

def get_pwd_leaks_count(hashes, hash_to_check):
    '''

    :param hashes: url responce object
    :param hash_to_check: hash tail
    :return:list - contains number of password usages
    '''
    hashes = (line.split(':') for line in hashes.text.splitlines())
    res = [i for i in filterbyvalue(hashes, hash_to_check)]
    if len(res):
        return res[0]
    return 0

def password_chk(password):
    '''
    Hashes password by SHA1 algorithm
    :param password: str
    :return: list - number of checked password usages
    '''

    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_pwd_leaks_count(response, tail)

def main(args):
    for passw in args:
        count = password_chk(passw)
        if count:
            print(f'{passw} was found {count} times')
        else:
            print(f'{passw} is strong enough')

if __name__ == '__main__':
    main(['123'])

    # main(sys.argv[1:])
   # sys.exit(main(sys.argv[1:])) - принудительный выход если что-то пошло не так и зависло
