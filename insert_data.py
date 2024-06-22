from datetime import datetime

import pandas as pd
from models import Product, Business
from tortoise import Tortoise, run_async

# الاتصال بقاعدة البيانات
async def init():
    await Tortoise.init(
        db_url="sqlite://database.sqlite3",
        modules={"models": ["models"]}
    )
    await Tortoise.generate_schemas()

# تحميل البيانات من ملف CSV وإدخالها إلى قاعدة البيانات
async def load_data_from_csv(file_path):
    data = pd.read_csv(file_path)
    for index, row in data.iterrows():
        business, created = await Business.get_or_create(
            business_name=row['Vendor'],
            defaults={
                'city': row['Location'],
                'region': "Unknown",
                'business_description': "",
                'logo': "default.jpg",
                'owner_id': 1  # تأكد من أن لديك مالكًا صالحًا مرتبطًا
            }
        )

        await Product.create(
            name=row['productDisplayName'],
            category=row['subCategory'],
            original_price=row['Price'],
            new_price=row['Price'],
            percentage_discount=0,
            offer_expiration_date=datetime.utcnow(),
            product_image=row['filename'],
            business=business
        )

if __name__ == "__main__":
    file_path = 'filtered_fashion_data.csv'  # استبدل هذا بالمسار الفعلي لملف CSV الخاص بك
    run_async(init())
    run_async(load_data_from_csv(file_path))
