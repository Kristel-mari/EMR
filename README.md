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