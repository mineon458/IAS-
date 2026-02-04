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

 Role-Based Access Control (RBAC)
- Two user roles: `admin` and `user`
- Protected routes using decorators
- Admin-only dashboard and user management
- Prevents direct URL access to protected pages

 Input Validation
- Email format validation
- Username validation (3-20 characters, alphanumeric + underscore only)
- Password strength validation
- SQL injection prevention through parameterized queries
- XSS protection through template auto-escaping

 Protected Routes
- `/` - Redirects to login or dashboard
- `/register` - Public registration
- `/login` - Public login
- `/dashboard` - Protected (login required)
- `/profile` - Protected (login required)
- `/change-password` - Protected (login required)
- `/admin` - Protected (admin only)
- `/logout` - Public logout

 Security Features
- Secure cookie flag for HTTPS
- Session timeout after a period of inactivity
- Database encryption for passwords
- CSRF protection in forms


Secure Web Application Project Structure

```
│
├── app.py
├── secure_app.db
├── README.md
│
├── templates/
│   ├── Index.html
│   ├── login.html
│   ├── registrationPage.html
│   ├── dashboard.html
│   ├── profile.html
│   ├── change_password.html
│   ├── admin.html
│   └── style.css   ❌ (this should not be here, but it won’t crash)
│
└── static/
    └── style.css   ✅ correct place

```

Usage Examples

 User Registration
1. Visit `/register`
2. Enter username, email, and password meeting requirements
3. Click "Register"
4. Login with your credentials

  Admin Access
1. Login with admin credentials
2. Navigate to Admin Panel
3. View all registered users

 Change Password
1. Login
2. Click "Change Password"
3. Enter current password and new password
4. Submit


