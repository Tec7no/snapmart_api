import logging
import smtplib
import uuid
from _pydatetime import timedelta
from contextvars import Token
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pyotp

from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware
from fastapi import HTTPException
from fastapi import BackgroundTasks
from tortoise.transactions import in_transaction
from datetime import datetime, timedelta
from insert_data import load_data_from_csv
from pydantic import BaseModel

import jwt
from fastapi import FastAPI, Request, HTTPException, status, Depends
from tortoise.contrib.fastapi import register_tortoise

# Authentication
from authentication import *
from fastapi.security import(OAuth2PasswordBearer, OAuth2PasswordRequestForm)

# signals
from tortoise.signals import post_save
from typing import List, Optional, Type
from tortoise import BaseDBAsyncClient
from emails import *

# response classes
from fastapi.responses import HTMLResponse
from models import user_pydanticIn, user_pydantic, business_pydantic, Business, Product, product_pydanticIn, \
    product_pydantic, business_pydanticIn, PasswordResetToken, NormalUser, NormalUserLogin, NormalUserRegistration, \
    MessageResponse, AuthToken, normal_user_pydanticIn, normal_user_pydantic, Account, account_pydantic, \
    normal_user_pydanticOut

# templates
from fastapi.templating import Jinja2Templates

# image upload
from fastapi import File, UploadFile
import secrets
from fastapi.staticfiles import StaticFiles
from PIL import Image
import os
from fastapi.responses import JSONResponse


app = FastAPI()

oath2_scheme = OAuth2PasswordBearer(tokenUrl='token')

# static file setup config
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.post('/token')
async def generate_token(request_from: OAuth2PasswordRequestForm = Depends()):
    token = await token_generator(request_from.username, request_from.password)
    return {"access_token" : token, "token_type" : "bearer"}

async def get_current_user(token: str = Depends(oath2_scheme)):
    try:
        payload = jwt.decode(token, config_credentials["SECRET"], algorithms=['HS256'])
        user = await User.get(id = payload.get("id"))

    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return await user

@app.post("/user/me")
async def user_login(user: user_pydanticIn = Depends(get_current_user)):
    business = await Business.get(owner=user)
    logo = business.logo #asl6as5d4.png
    logo_path = "localhost:8000/static/images"+logo

    return {
        "status": "ok",
        "data": {
            "username": user.username,
            "email": user.email,
            "verified": user.is_verified,
            "joined_date": user.join_date.strftime("%b %d %Y"),
            "logo": logo_path
        }
    }


@post_save(User)
async def create_business(
        sender: "Type[User]",
        instance: User,
        created: bool,
        using_db: "Optional[BaseDBAsyncClient]",
        update_fields: List[str]
) -> None:
    if created:
        business_obj = await Business.create(
            business_name=instance.username, owner=instance
        )

        await business_pydantic.from_tortoise_orm(business_obj)
        # send the email
        await send_email([instance.email], instance)


templates = Jinja2Templates(directory="templates")


@app.get('/verification', response_class=HTMLResponse)
async def email_verification(request: Request, token: str):
    try:
        user = await verify_token(token)
        if user and not user.is_verified:
            user.is_verified = True
            await user.save()
            return templates.TemplateResponse("verification.html",
                                              {"request": request, "username": user.username})
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )



@app.post("/registration")
async def user_registrations(user: user_pydanticIn):
    user_info = user.dict(exclude_unset=True)
    user_info["password"] = get_hashed_password(user_info["password"])
    user_obj = await User.create(**user_info)
    new_user = await user_pydantic.from_tortoise_orm(user_obj)
    return {
        "status": "ok",
        "data": f"Hello {new_user.username} , thanks for choosing snapmart. please check your email inbox and click on the link to verify your account .",
    }




@app.get("/")
def index():
    return {"Message": "Hello World"}

@app.post("/uploadfile/profile")
async def create_upload_file(file: UploadFile = File(...),
                             user: user_pydantic = Depends(get_current_user)):
    FILEPATH = "./static/images"
    filename = file.filename
    # test.png >> ["test", "png"]
    extenstion = filename.split(".")[1]

    if extenstion not in ["png","jpg","jpeg"]:
        return {"status" : "error", "detail": "File extenstion not allowed"}

    # /static/images/asgasg.png
    token_name = secrets.token_hex(10) + "."+extenstion
    generate_name = FILEPATH + token_name
    file_content = await file.read()

    with open(generate_name, "wb") as file:
        file.write(file_content)

    # PILLOW
    img = Image.open(generate_name)
    img = img.resize(size = (200, 200))
    img.save(generate_name)

    file.close()

    business = await Business.get(owner = user)
    owner = await business.owner

    if owner == user:
        business.logo = token_name
        await business.save()
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not Authenticated to perform this action",
            headers={"WWW-Authenticate": "Bearer"}
        )

    file_url = "localhost:8000"+ generate_name[1:]
    return {"status": "ok", "filename": file_url}

@app.post("/uploadfile/product/{id}")
async def create_upload_file(id: int, file: UploadFile = File(...),
                             user: user_pydanticIn = Depends(get_current_user)):
    FILEPATH = "./static/images"
    filename = file.filename
    # test.png >> ["test", "png"]
    extenstion = filename.split(".")[1]

    if extenstion not in ["png","jpg","jpeg"]:
        return {"status" : "error", "detail": "File extenstion not allowed"}

    # /static/images/asgasg.png
    token_name = secrets.token_hex(10) + "."+extenstion
    generate_name = FILEPATH + token_name
    file_content = await file.read()

    with open(generate_name, "wb") as file:
        file.write(file_content)

    # PILLOW
    img = Image.open(generate_name)
    img = img.resize(size = (200, 200))
    img.save(generate_name)

    file.close()

    product = await Product.get(id=id)
    business = await product.business
    owner = await business.owner

    if owner == user:
        product.product_image = token_name
        await product.save()
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated to perform this action",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Assuming your server is running locally on port 8000
    file_url = "http://localhost:8000/static/images/" + token_name
    return {"status": "ok", "filename": file_url}


# CRUD functionality
@app.post("/products")
async def add_new_product(product: product_pydanticIn,
                            user: user_pydantic = Depends(get_current_user)):

    product = product.dict(exclude_unset=True)

    # to avoid division error by zero
    if product["original_price"] > 0:
        product["percentage_discount"] = ((product["original_price"] - product["new_price"]) / product["original_price"]) * 100

        product_obj = await Product.create(**product, business = user)
        product_obj = await product_pydantic.from_tortoise_orm(product_obj)

        return {"status": "ok", "data": product_obj}

    else:
        return {"status": "Error"}

@app.post("/product")
async def get_product():
    response = await product_pydantic.from_queryset(Product.all())
    return {"status":"ok", "data":response}

@app.get("/product/{id}")
async def get_product(id: int):
    product = await Product.get(id = id)
    business = await product.business
    owner = await business.owner
    response = await product_pydantic.from_queryset_single(Product.get(id = id))

    return {
        "status" : "ok",
        "data": {
            "product_details" : response,
            "business_details": {
                        "name" : business.business_name,
                        "city" : business.city,
                        "region": business.region,
                        "description" : business.business_description,
                        "logo" : business.logo,
                        "owner_id" : owner.id,
                        "business_id": business.id,
                        "join_date": owner.join_date.strftime("%b %d %Y")
                    }
                }
            }

@app.delete("/product/{id}")
async def delete_product(id: int , user: user_pydantic = Depends(get_current_user)):
    product = await Product.get(id = id)
    business = await product.business
    owner = await business.owner

    if user == owner:
        product.delete()
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated to perform this action",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return {"status" : "ok"}

@app.put("/product/{id}")
async def update_product(id: int, update_info: product_pydanticIn, user: user_pydantic = Depends(get_current_user)):
    product = await Product.get(id = id)
    business = await product.business
    owner = await business.owner

    update_info = update_info.dict(exclude_unset=True)
    update_info["date_published"] = datetime.utcnow()

    if user == owner and update_info["original_price"] > 0:
        update_info["percentage_discount"] = ((update_info["original_price"]
                                               - update_info["new_price"]) / update_info["original_price"]) * 100
        product = await product.update_from_dict(update_info)
        product.save()
        response = await product_pydantic.from_tortoise_orm(product)
        return {"status": "ok", "date": response}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated to perform this action or invalid user input",
            headers={"WWW-Authenticate": "Bearer"}
        )

@app.put("/business/{id}")
async def update_business(id: int, update_business: business_pydanticIn, user: user_pydantic = Depends(get_current_user)):

    update_business = update_business.dict()

    business = await Business.get(id=id)
    business_owner = await business.owner

    if user == business_owner:
        await business.update_from_dict(update_business)
        business.save()
        response = await business_pydantic.from_tortoise_orm(business)
        return {"status": "ok", "date": response}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated to perform this action",
            headers={"WWW-Authenticate": "Bearer"}
        )


origins = [
    "http://localhost",
    "http://localhost:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# إعداد تسجيل الأخطاء
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

oath2_scheme = OAuth2PasswordBearer(tokenUrl='token')

async def get_current_user(token: str = Depends(oath2_scheme)):
    try:
        payload = jwt.decode(token, config_credentials["SECRET"], algorithms=['HS256'])
        user = await User.get(id = payload.get("id"))

    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return await user

@app.post("/uploadfile/csv")
async def upload_csv_file(file: UploadFile = File(...), user: user_pydanticIn = Depends(get_current_user)):
    file_location = f"{file.filename}"
    with open(file_location, "wb+") as file_object:
        file_object.write(file.file.read())

    await load_data_from_csv(file_location)
    return {"info": "file processed successfully"}



@app.put("/user/change-password")
async def change_password_endpoint(new_password: str, current_password: str, user: user_pydanticIn = Depends(get_current_user)):
    # Retrieve user from database
    user_obj = await User.get(username=user.username)

    # Verify the current password
    if not await verify_password(current_password, user_obj.password):
        raise HTTPException(status_code=400, detail="Incorrect current password")

    # Hash the new password
    hashed_password = get_hashed_password(new_password)

    # Update the user's password
    user_obj.password = hashed_password
    await user_obj.save()

    return {"status": "ok", "message": "Password updated successfully"}

register_tortoise(
    app,
    db_url="sqlite://database.sqlite3",
    modules={"models": ["models"]},
    generate_schemas=True,
    add_exception_handlers=True
)

oauth2_scheme_normal = OAuth2PasswordBearer(tokenUrl='token_normal')

# Token generator function (replace with your implementation)
async def token_generator(username: str, password: str) -> str:
    # Dummy implementation
    user = await NormalUser.get(username=username)  # Assuming you validate the user here
    payload = {"id": user.id, "exp": datetime.utcnow() + timedelta(hours=1)}
    return jwt.encode(payload, config_credentials["SECRET"], algorithm='HS256')

@app.post('/token_normal')
async def generate_token(request_from: OAuth2PasswordRequestForm = Depends()):
    token_normal = await token_generator(request_from.username, request_from.password)
    return {"access_token": token_normal, "token_type": "bearer"}

async def get_current_normal_user(token_normal: str = Depends(oauth2_scheme_normal)):
    try:
        payload = jwt.decode(token_normal, config_credentials["SECRET"], algorithms=['HS256'])
        user = await NormalUser.get(id=payload.get("id"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user

@app.post("/normal_user/me")
async def user_login(user: normal_user_pydanticIn = Depends(get_current_normal_user)):
    account = await Account.get(owner=user)
    logo = account.logo  # e.g., asl6as5d4.png
    logo_path = f"http://localhost:8000/static/images/{logo}"

    return {
        "status": "ok",
        "data": {
            "username": user.username,
            "email": user.email,
            "verified": user.is_verified,
            "joined_date": user.join_date.strftime("%b %d %Y"),
            "logo": logo_path
        }
    }

@post_save(NormalUser)
async def create_account(
        sender: Type[NormalUser],
        instance: NormalUser,
        created: bool,
        using_db: Optional[BaseDBAsyncClient],
        update_fields: List[str]
) -> None:
    if created:
        account_obj = await Account.create(account_name=instance.username, owner=instance)
        await account_pydantic.from_tortoise_orm(account_obj)
        await send_email([instance.email], instance)  # Assuming send_email is defined

@app.get('/verification_normal', response_class=HTMLResponse)
async def email_verification(request: Request, token_normal: str):
    try:
        user = await verify_token(token_normal)  # Assuming verify_token is defined
        if user and not user.is_verified:
            user.is_verified = True
            await user.save()
            return templates.TemplateResponse("verification.html", {"request": request, "username": user.username})
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already verified or token is invalid",
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.post("/registration_normal")
async def user_registrations(user: normal_user_pydanticIn):
    user_info = user.dict(exclude_unset=True)
    user_info["password"] = get_hashed_password(user_info["password"])  # Assuming get_hashed_password is defined
    user_obj = await NormalUser.create(**user_info)
    new_user = await normal_user_pydantic.from_tortoise_orm(user_obj)
    return {
        "status": "ok",
        "data": f"Hello {new_user.username}, thanks for choosing snapmart. Please check your email inbox and click on the link to verify your account.",
    }


def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
if __name__ == "__main__":
    main()