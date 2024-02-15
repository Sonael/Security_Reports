import requests

url = "http://testphp.vulnweb.com/userinfo.php?"


data1 = {"uname": "testdasdas", "pass": "testdasda"}
data = "uname=test&pass=test"

# Content-Type: application/x-www-form-urlencoded
headers = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0'}


#tamanho da requisição
r = requests.post("http://testphp.vulnweb.com/userinfo.php?", data=data1, headers=headers)
print(r.status_code)




