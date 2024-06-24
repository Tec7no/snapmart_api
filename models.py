from tortoise import fields
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model
from datetime import datetime, timedelta
import uuid
from pydantic import BaseModel


class PasswordResetToken(Model):
    id = fields.IntField(pk=True)
    user = fields.ForeignKeyField('models.Vendor', related_name='password_reset_tokens', null=True)
    token = fields.UUIDField(default=uuid.uuid4)
    expires_at = fields.DatetimeField()

    class Meta:
        table = "password_reset_tokens"

    @classmethod
    async def create_with_expiration(cls, user=None, normal_user=None, reset_token=uuid.uuid4()):
        expires_at = datetime.utcnow() + timedelta(hours=1)
        instance = cls(user=user, normal_user=normal_user, token=reset_token, expires_at=expires_at)
        await instance.save()
        return instance


class MessageResponse(BaseModel):
    message: str


class AuthToken(BaseModel):
    access_token: str
    token_type: str


class Vendor(Model):
    id = fields.IntField(pk=True, index=True)
    username = fields.CharField(max_length=20, null=False, unique=True)
    email = fields.CharField(max_length=200, null=False, unique=True)
    password = fields.CharField(max_length=100, null=False)
    is_verified = fields.BooleanField(default=False)
    join_date = fields.DatetimeField(default=datetime.utcnow)


class Business(Model):
    id = fields.IntField(pk=True, index=True)
    business_name = fields.CharField(max_length=20, null=False, unique=True)
    city = fields.CharField(max_length=100, null=False, default="Unspecified")
    postal_code = fields.CharField(max_length=100, null=False, default="Unspecified")
    business_description = fields.TextField(null=True)
    logo = fields.CharField(max_length=200, null=False, default="default.jpg")
    owner = fields.ForeignKeyField("models.Vendor", related_name="businesses")


class Product(Model):
    id = fields.IntField(pk=True, index=True)
    name = fields.CharField(max_length=100, null=False, index=True)
    category = fields.CharField(max_length=30, index=True)
    original_price = fields.DecimalField(max_digits=12, decimal_places=2)
    new_price = fields.DecimalField(max_digits=12, decimal_places=2)
    percentage_discount = fields.IntField()
    offer_expiration_date = fields.DatetimeField(default=datetime.utcnow)
    date_published = fields.DatetimeField(default=datetime.utcnow)
    product_image = fields.CharField(max_length=200, null=False, default="productDefault.jpg")
    business = fields.ForeignKeyField("models.Business", related_name="products")


class ChangePassword(BaseModel):
    current_password: str
    new_password: str


# Pydantic models creation
user_pydantic = pydantic_model_creator(Vendor, name="Vendor", exclude=("is_verified",))
user_pydanticIn = pydantic_model_creator(Vendor, name="VendorIn", exclude_readonly=True, exclude=("is_verified", "join_date"))
user_pydanticOut = pydantic_model_creator(Vendor, name="VendorOut", exclude=("password",))

business_pydantic = pydantic_model_creator(Business, name="Business")
business_pydanticIn = pydantic_model_creator(Business, name="BusinessIn", exclude=("logo", "id"))

product_pydantic = pydantic_model_creator(Product, name="Product")
product_pydanticIn = pydantic_model_creator(Product, name="ProductIn", exclude=("percentage_discount", "id", "product_image", "date_published"))
