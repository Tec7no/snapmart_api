first u have to creat 
.env file 

EMAIL = ""
PASS = ""
SECRET = ""

Email & Password depend on your smtp server you use 
i am using "https://ethereal.email/" .

SECRET you generate locally from python .

if you wanna use gmail smtp first change the smtp server in conf you will find variable 
called MAIL_SERVER change it smtp.gmail.com in "email.py".

creat directory like that "static\images" to save your upload image .

that's all you need to run the api .