import requests
import hashlib
import sys

# this function allows to connect with the api and returns the response


def request_ipa(ech_key):
    url = 'https://api.pwnedpasswords.com/range/' + ech_key
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'[{res.status_code}], check the api and try again')
    return res

# this function allows to split the hashes(resonse) into hashe and count and resturns how many time we found hashe_to_check


def get_password_count(hashes, hashe_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, nbr_hash_found in hashes:
        if(h == hashe_to_check):
            return nbr_hash_found
    return 0

# this function takes a pssd as param in return how many times we has been hhacked.


def pssd_hacked_checker(pssd):
    hash_password = hashlib.sha1(pssd.encode('utf-8')).hexdigest().upper()
    first5_chars, rest_chars = hash_password[:5], hash_password[5:]
    res = request_ipa(first5_chars)
    return get_password_count(res, rest_chars)

# to check the input pass word


def main(args):
    for pssd in args:
        nbrs = pssd_hacked_checker(pssd)
        if nbrs:
            print(f'{pssd}: was found [{nbrs}] times. you must change it.')
        else:
            print(f"{pssd}: was found [{nbrs}] times. it is save.")


if __name__ == "__main__":
    main(sys.argv[1:])
