# A simple script to automate the process of encoding database record.

from app import Examinee, db
from datetime import date

db.drop_all()
db.create_all()

examinees = [
    Examinee(
        username='fash22', password='password',first_name='John Rey', middle_name='Sabanal', last_name='Faciolan',
        first_priority='bsit', second_priority='bsentrep', third_priority='beed',
        school='TUPVisayas', graduated=date(2019,3,15)
    ),
Examinee(
        username='shemoymoy', password='password',first_name='Shem', middle_name='Castro', last_name='Himarangan',
        first_priority='bsit', second_priority='bsentrep', third_priority='beed',
        school='TUPVisayas', graduated=date(2019,3,15)
    ),
Examinee(
        username='teensy', password='password',first_name='Martina', middle_name='Bologna', last_name='Estupado',
        first_priority='bsit', second_priority='bsentrep', third_priority='beed',
        school='TUPVisayas', graduated=date(2019,3,15)
    ),
Examinee(
        username='mitzie', password='password',first_name='Menchin', middle_name='Luces', last_name='Ginoabo',
        first_priority='bsit', second_priority='bsentrep', third_priority='beed',
        school='TUPVisayas', graduated=date(2019,3,15)
    ),
]

db.session.add_all(examinees)
db.session.commit()