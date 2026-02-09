Secure Web Application

A production-ready web application with comprehensive security features including authentication, password hashing, role-based access control, and input validation.

Features of Secure Web Application

✅ User Authentication
- Registration with email verification requirements
- Secure login with session management
- Logout functionality with session clearing

✅ Password Security
- Hashing algorithm
- Strong password requirements:
  - Minimum 8 characters
  - Must include uppercase and lowercase letters
  - Must include at least one digit
  - Must include at least one special character (!@#$%^&*)
- Secure password change functionality

✅ Role-Based Access Control (RBAC)
- Two user roles: `admin` and `user`
- Protected routes using decorators
- Admin-only dashboard and user management
- Prevents direct URL access to protected pages

✅ Input Validation
- Email format validation
- Username validation (3-20 characters, alphanumeric + underscore only)
- Password strength validation
- SQL injection prevention through parameterized queries
- XSS protection through template auto-escaping

Secure Web Application Project Structure

```
│
├── py_cache_
├── instance
│   ├── secure_app.db
│
├── static
│   ├── README.txt
│   ├── style.css
│
├── templates/
│   ├── 403.html
│   ├── 404.html
│   ├── 500.html
│   ├── admin.html
│   ├── change_password.html
│    ├── dashboard.html
│    ├── edit_admin.html
│    ├── login.html
│    ├── profile.html
│    ├── registration.html
│ 
├── app.py
└── README.md

```
  - ROLES -
Python and Flask Integration - Dumangas
Password Security - Tahanlangit
HTML sytling - Tahanlangit
Terminal Debugging - Dumangas
Password Updates - Narte