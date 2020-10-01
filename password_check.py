import requests
import hashlib
from pathlib import Path
import csv
import sys
import importlib.util


def filterbyvalue(seq, value):
    '''
    Finds hash tail in url responce text
    :param seq:
    :param value:
    :return:
    '''
    for el in seq:
        if el[0] == value:
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

def get_passwords_from_txt(txt_file):
    '''
    :param txt_file: Path object - path to txt file
    :return:list - list of passwords from txt file
    '''

    if not txt_file.is_file():
        return []

    ls = []

    with txt_file.open('r') as f:
        for password in f.readlines():
            ls.append(password)
    return ls

def get_passwords_from_csv(csv_file, pwd_row_name = 'password'):
    '''
    :param csv_file: Path object - path to csv file
    :return: list - list of passwords from txt file
    '''
    if not csv_file.is_file():
        return []

    ls = []

    with csv_file.open('r', newline='') as csvfile:

       reader = csv.DictReader(csvfile) #using DictReader to automatically deal with header row

       if pwd_row_name not in reader.fieldnames:
           raise NameError(f'No such column is csv file \'{pwd_row_name}\'')


       for row in reader:
            ls.append(row[pwd_row_name])

    return ls

def get_passwords_from_xls(xls_file):
    '''
    TODO
    :param xls_file: Path object - path to xls file
    :return:
    '''

    spec = importlib.util.find_spec('openpyxl') #checks for istalled module 'openpyxl'
    if spec is None:
        raise ImportError(f'Module \'openpyxl\' is not installed')
    else:
        spec.loader.exec_module('openpyxl')


def main(args):
    for passw in args:
        count = password_chk(passw)
        if count:
            print(f'{passw} was found {count} times')
        else:
            print(f'{passw} is strong enough')


if __name__ == '__main__':

    # sys.exit(main(sys.argv[1:]))

    # cmd_params = ['123', '667895','sgaad5784484&^%%$']
    # cmd_params = ['./test_files/passwords.txt']
    # cmd_params = ['./test_files/passwords.csv']
    cmd_params = ['./test_files/passwords.xlsx']

    # cmd_params = sys.argv[1:]
    # print(cmd_params)

    passwd_list = []
    file_extension = cmd_params[0][-4:]
    if file_extension == '.txt':
        txt_file = Path(cmd_params[0])
        passwd_list = get_passwords_from_txt(txt_file)
    elif file_extension == '.csv':
        csv_file = Path(cmd_params[0])
        if len(cmd_params)>1:
           passwd_list = get_passwords_from_csv(csv_file, cmd_params[1])
        else:
            passwd_list = get_passwords_from_csv(csv_file)
    elif file_extension =='.xls' or file_extension == 'xlsx':
        xls_file = Path(cmd_params[0])
        passwd_list = get_passwords_from_xls(xls_file)
    else:
        passwd_list = sys.argv[1:]

    if len(passwd_list):
        main(passwd_list)
