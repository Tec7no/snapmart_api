from fastapi import HTTPException
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from dotenv import dotenv_values
import jwt
from models import User

# Load environment variables
config_credentials = dotenv_values(".env")

# Define ConnectionConfig with credentials
conf = ConnectionConfig(
    MAIL_USERNAME=config_credentials["EMAIL"],
    MAIL_PASSWORD=config_credentials["PASS"],
    MAIL_FROM=config_credentials["EMAIL"],
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,  # Specify STARTTLS for TLS encryption
    MAIL_SSL_TLS=False,  # Specify SSL/TLS, False means not using SSL/TLS
    USE_CREDENTIALS=True,
)





# In send_email function
async def send_email(email: str, instance: User):  # Change email to str instead of List[str]
    token_data = {
        "id": instance.id,
        "username": instance.username
    }

    token = jwt.encode(token_data, config_credentials["SECRET"], algorithm='HS256')

    template = f"""
        <!DOCTYPE HTML>
        <html>
        <head>
        </head>
        <body>
            <div style="display: flex; align-items: center; justify-content: center; flex-direction: column;"> 
                <h3>Account Verification</h3>
                <br>
                <p>Thanks for choosing SnapMart, please click on the button below to verify your account</p>
                <a style="margin-top: 1rem; padding: 1rem; border-radius: 0.5rem; font-size: 1rem; text-decoration: none; background: #0275d8; color: white;" href="http://localhost:8000/verification/?token={token}">Verify your email</a>    
                <p>Please kindly ignore this email if you did not register for SnapMart and nothing will happen. Thanks</p>
            </div>
        </body>
        </html>
    """

    message = MessageSchema(
        subject="SnapMart Account Verification Email",
        recipients=email,  # Corrected spelling of recipients
        body=template,
        subtype="html"
    )

    fm = FastMail(conf)
    await fm.send_message(message=message)




