# EMR

Simple Flask-based secure EMR starter app.

## Security improvements included

- Password hashing (Werkzeug)
- Audit logging for user actions
- CSRF protection for all POST forms
- Role-based access control for adding patients (admin only)
- Hardened session cookie settings (`HttpOnly`, `SameSite=Lax`, optional `Secure`)
- Secret key loaded from environment variable (`EMR_SECRET_KEY`)

## Run locally

```bash
pip install -r requirements.txt
export EMR_SECRET_KEY="replace-with-a-long-random-secret"
python app.py
```

To force secure cookies (recommended behind HTTPS):

```bash
export EMR_SECURE_COOKIE=1
```

MD login:
- Username: `admin`
- Password: `Admin123!`

Nurse login:
- Username: 'nurse'
- Password: 'Nurse123!'

IT admin login:
- Username: 'itadmin' 
- Password: 'ITadmin123!'

Pharmacy login:
- Username: pharmacy
- Password: Pharmacy123!

AxonEMR is an educational portfolio project created for learning purposes. It is not affiliated with or endorsed by any existing company or trademark holder.

<img width="3767" height="1777" alt="Capture" src="https://github.com/user-attachments/assets/87aab030-744e-4228-9eae-6ab99ea7bc58" />
<img width="3782" height="1790" alt="IThome" src="https://github.com/user-attachments/assets/983bfd5a-f191-4016-83e3-07da127b00bd" />
<img width="3757" height="1772" alt="Nursehome" src="https://github.com/user-attachments/assets/47958b57-6ad4-490c-a55d-8337ad722926" />
<img width="3760" height="1777" alt="Providerhome" src="https://github.com/user-attachments/assets/2491e69a-2da8-4831-97a4-592c722c3ea9" />
<img width="3736" height="1778" alt="Rxhome" src="https://github.com/user-attachments/assets/9497af45-b157-4ae5-b290-383b0ac3925d" />
<img width="3771" height="1790" alt="labs" src="https://github.com/user-attachments/assets/67b5370e-5fab-490a-97c1-38b4a3664e03" />




