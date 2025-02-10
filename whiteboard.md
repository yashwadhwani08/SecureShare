

**Functional Requirements:**

- User Login / Logout
	- MFA Authenticaion (Okta/Google Authenticator)
- Role Based Access Control
	- SuperAdmin: Can do everything with all files
	- User: Can download, upload, view own files + files shared with user
	- Guest: Can only view certain files
- Encryption
	- Encrypt data in motion -> User uploads file -> Add it to Encryption Queue-> Backend processes and encrypts file -> Encrypted file is stored in Storage
	- Once download is triggered, transfer file from server->client, then decrypt it at client machine
- File Sharing
	- User can share file with another user, can assign them view or download permission
	- When a sharing link is created, it will be live only for X minutes


Technical Requirements:

- Backend: Python + Django
- Frontend: TypeScript + React
- Redux for state management
- To Explore: NoSQL/SQL/Firebase ->
- Authentication: JWT
- MFA: Some provider
- Certificate Management
- Make sure credentials are hashed


Action Items:
1. Decide what type of database to use
2. Figure out how to implement MFA and which provider to use
3. Create GitHub repository
4. Figure out how to implement encryption of data





Files:
- Bucket Storage platform  (s3)
- File Meta Data
	- FileID
	- FileName
	- Size
	- SharedStatus
	- SharedWith
	- SharePermissions
	- Owner

    DeepSeek Response:

    Intermediate Response:
    Okay, let's tackle this problem. The user wants a secure file-sharing web application with specific functional and technical requirements. Let me start by breaking down the requirements to understand what needs to be done.

First, the functional requirements include user login/logout with MFA, role-based access control (SuperAdmin, User, Guest), encryption during transit and at rest, and time-limited file sharing. The technical stack is Python/Django for backend, TypeScript/React/Redux for frontend, and a choice between NoSQL/SQL/Firebase. Authentication uses JWT with MFA via a provider like Okta or Google Authenticator. Also, credentials must be hashed, and certificate management is needed.

Starting with the backend. Since it's Django, I can use Django's built-in models for users, but since we need roles (SuperAdmin, User, Guest), maybe a custom user model with roles. Also, JWT authentication would be needed. For MFA, integrating with Okta or Google Authenticator. Let's see, Django has packages like django-allauth for OAuth, but MFA might require using a third-party service's API. Okta has SDKs, so maybe using their API for MFA verification.

Next, encryption. The files need to be encrypted when stored. So when a user uploads a file, it goes into a queue, and the backend encrypts it before storing. For encryption, maybe use AES with a per-file key, which is then encrypted with a public key and stored. But key management is tricky. Alternatively, use a library like cryptography in Python. The encryption should happen server-side after upload, so the file is stored encrypted. Then, when downloading, the client gets the encrypted file and decrypts it using a key. Wait, but how does the client get the decryption key securely? Maybe the key is encrypted and sent along with the file, but the client needs to have the decryption key. Hmm. Or perhaps use asymmetric encryption where the server holds the private key and the client uses a public key? Not sure. Need to think about secure key transfer.

File sharing: users can share files with others, assign view/download permissions. Sharing links expire after 10 minutes. So, when a user shares a file, a unique link is generated with an expiration timestamp. The backend needs to check the validity of the link upon access. For permissions, maybe a model that links the file, the recipient user (or a token for guests), permissions (view/download), and expiration time.

Database choice: The technical requirements mention exploring NoSQL/SQL/Firebase. Since Django is ORM-based and traditionally uses SQL databases like PostgreSQL, maybe stick with PostgreSQL for ACID compliance. But if there's a need for scalability, maybe Firebase for real-time features. However, given that Django works best with relational data, especially for RBAC and file permissions, SQL might be better. Let's go with PostgreSQL for the backend.

Certificate management: Need to handle SSL/TLS for data in motion. That's usually handled by the web server (Nginx, Apache) or a cloud provider. But the application itself might not handle certificate management if using a service like Let's Encrypt. However, the requirement might refer to managing encryption keys for file encryption. So using a key management service or secure storage for encryption keys, maybe AWS KMS or HashiCorp Vault. But since the user said "to explore", perhaps using Django's security features to store keys in environment variables, though not the most secure. Alternatively, generate a key per file, encrypt it with a master key, and store the master key in a secure vault.

Frontend: React with TypeScript and Redux. So components for login, file upload, sharing, etc. The frontend needs to handle JWT tokens, MFA setup/verification, and file encryption/decryption. Wait, the encryption during upload is handled server-side via a queue, but decryption is client-side. So when a user downloads a file, the encrypted file is sent, and the client must decrypt it. So the client needs the decryption key. How is that key transmitted securely? Maybe the key is sent via an API endpoint that's only accessible when the user has the right permissions, and it's encrypted over HTTPS. So when a user requests to download a file, the backend sends the encrypted file and the decryption key (perhaps encrypted with the user's public key if using asymmetric encryption). But this complicates things. Alternatively, use symmetric encryption where the key is stored encrypted in the database and sent to the client upon authorized download. But then the key must be securely transmitted. Maybe using JWE (JSON Web Encryption) to encrypt the key in transit.

Now, putting it all together:

Backend Structure:

- Django project with apps for authentication, files, sharing.

- Models:

- CustomUser: extends AbstractUser with role field (SuperAdmin, User, Guest).

- File: stores encrypted file metadata, owner, upload time, encryption key (encrypted).

- ShareLink: file, shared_with user (or email?), permissions, expiration time, token for the link.

- Authentication using JWT. For MFA, when a user logs in, after username/password, they must provide a TOTP code. Use a package like django-otp or integrate with Okta's API.

- Encryption queue: when a file is uploaded, it's stored temporarily, then a task (Celery?) processes it: encrypts the file, stores it in the storage (S3 or filesystem), saves the encrypted key in the database.

- File download: when a user requests a file, check permissions. If allowed, send the encrypted file and the decryption key (encrypted?). The client then decrypts it using JavaScript libraries like crypto-js.

Frontend Structure:

- Login page with MFA input.

- File upload component: uploads file to backend, which queues it for encryption.

- File list showing user's files and shared files.

- Share button: opens a dialog to enter user email and permissions, generates a share link with expiration.

- Download button: fetches encrypted file and key, decrypts in the browser.

Security considerations:

- HTTPS is a must for data in motion.

- Passwords are hashed (Django's default uses PBKDF2, which is good).

- JWT tokens stored securely (httpOnly cookies).

- MFA enforced for all users except maybe guests.

- Rate limiting on authentication endpoints.

- Encryption keys managed securely; perhaps use a Key Management Service.

- File storage encrypted at rest (could use S3 server-side encryption along with application-level encryption).

Potential challenges:

- Handling large file uploads with encryption might require chunking.

- Client-side decryption requires a secure way to handle keys. If the key is sent alongside the file, it's encrypted in transit but needs to be decrypted in the client. Need to ensure the client's environment is secure.

- Managing encryption queues efficiently to prevent bottlenecks.

- Share link expiration must be strictly enforced, possibly with a background task to clean up expired links.

Testing:

- Unit tests for permission checks, encryption/decryption.

- Integration tests for file sharing, MFA flow.

- E2E tests for user workflows.

Third-party services:

- For MFA, Okta provides APIs for TOTP. Alternatively, use django-two-factor-auth which supports TOTP.

- File storage could be local or cloud-based (AWS S3, encrypted).

- Redis or RabbitMQ for task queue (Celery).

Now, let's outline the steps to implement:

1. Set up Django project and apps.

2. Create CustomUser model with roles.

3. Implement JWT authentication using djangorestframework-simplejwt.

4. Integrate MFA: maybe use pyotp to generate TOTP codes, have users scan a QR code during setup.

5. Set up Celery for encryption tasks.

6. Design File model with encryption details.

7. Implement file upload handling: upon upload, add to queue, Celery worker encrypts and stores.

8. File download: retrieve encrypted file and send decryption key (encrypted with user's key? Or session key).

9. File sharing: create ShareLink model with expiration, generate unique URLs, check permissions on access.

10. Frontend components for login (with MFA), file management, sharing.

11. Client-side decryption using crypto-js or similar.

12. Testing and security audits.

Possible code structure:

Backend models:

class CustomUser(AbstractUser):

ROLES = (('SUPERADMIN', 'SuperAdmin'), ('USER', 'User'), ('GUEST', 'Guest'))

role = models.CharField(max_length=20, choices=ROLES, default='USER')

mfa_secret = models.CharField(max_length=255, null=True, blank=True)

class File(models.Model):

owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

encrypted_file = models.FileField(upload_to='encrypted_files/')

encryption_key = models.BinaryField()  # Encrypted with server's public key or KMS

iv = models.BinaryField()  # Initialization vector for AES

uploaded_at = models.DateTimeField(auto_now_add=True)

class ShareLink(models.Model):

file = models.ForeignKey(File, on_delete=models.CASCADE)

token = models.CharField(max_length=100, unique=True)

shared_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)

shared_with = models.ForeignKey(CustomUser, null=True, blank=True, on_delete=models.CASCADE)  # or email?

permissions = models.CharField(max_length=10, choices=(('VIEW', 'View'), ('DOWNLOAD', 'Download')))

expires_at = models.DateTimeField()

created_at = models.DateTimeField(auto_now_add=True)

APIs:

- POST /api/login (username, password) → returns JWT after MFA verification.

- POST /api/mfa-verify (code) → returns JWT if correct.

- POST /api/upload → accepts file, adds to queue, returns file ID.

- GET /api/files → lists user's files and shared files.

- POST /api/share → creates a share link.

- GET /api/download/<file_id> → returns encrypted file and decryption key (secured).

Frontend:

- Use axios for API calls, store JWT in Redux state or context.

- FileUpload component with drag-and-drop.

- Handling MFA setup: after login, prompt for MFA code if not set up, else require it.

Encryption flow:

On upload:

1. User selects file, frontend uploads to /api/upload.

2. Backend saves the file temporarily, creates a File entry with status 'pending'.

3. Celery task picks up the file, encrypts it using AES-256-CBC with a random key and IV.

4. Encrypted file is saved to storage, encryption key is encrypted using a server's public key (RSA) and stored.

5. File status updated to 'encrypted'.

On download:

1. User clicks download, frontend requests /api/download/<file_id>.

2. Backend checks permissions, retrieves encrypted file and encrypted key.

3. Backend decrypts the encryption key using server's private key, then sends the encrypted file and decryption key (over HTTPS).

4. Frontend uses crypto-js to decrypt the file using the key and IV.

Security aspects here: the server's private key must be securely stored. Using a KMS would be better, but for simplicity, maybe store it in an environment variable, though that's not ideal.

Alternative approach: Use a key derivation function for each file, but that's more complex.

Another thing: The client needs to handle decryption. So the decryption key must be sent securely. If sent over HTTPS in the response body, it's encrypted in transit. Then, the client can use the key to decrypt the file. However, the key is exposed in the client's memory. But since the user is authorized to download the file, this might be acceptable if the key is only sent once and the client is trusted.

Potential risks: If an attacker gains access to the download endpoint, they could get the decryption key. So proper permission checks are essential.

Testing this would involve ensuring that only authorized users can access the decryption key and that the encryption/decryption process works correctly.

For the MFA integration, using pyotp in Django. When a user enables MFA, generate a secret key, store it in the user's mfa_secret field. Generate a QR code for the user to scan with Google Authenticator. During login, after password verification, the user must enter the TOTP code generated by the app.

In the login flow:

1. POST /api/login with username and password.

2. If correct, check if MFA is enabled for the user.

3. If MFA is enabled, return a response indicating MFA is required, frontend prompts for the code.

4. POST /api/login/mfa with the code, which is verified against the stored secret.

This requires modifying the JWT issuance to only happen after MFA verification if the user has MFA enabled.

For role-based access, middleware or decorators can check the user's role. For example, a decorator @superadmin_required for certain views.

File sharing implementation:

When a user shares a file, the backend generates a unique token (UUID), sets expiration time (now + 10 minutes), and stores it in ShareLink. The frontend then constructs a URL like /share/{token}. When accessing the share link, the backend checks if the token is valid and not expired. If valid, the user (even a guest) can view or download based on the permissions.

Guests might not have user accounts, so the ShareLink could have an email field or be accessible by anyone with the link. However, the requirement says guests can view certain files, so perhaps the share link grants temporary guest access.

Alternatively, guests are users with the Guest role, but how are they authenticated? Maybe the share link allows access without login, but that's a security risk. So perhaps when a user creates a share link, they can choose to make it public (for guests) or specify a user. For public links, the guest can access without logging in, but the link expires in 10 minutes. However, this would require a way to handle unauthenticated access for certain routes, which might conflict with JWT authentication. So, the share link endpoint would be public, but check the token's validity and expiration.

For example, a GET /api/share/{token} would return the file metadata if valid, and then allow download or view based on permissions. But downloading would still require the decryption key, which would need to be sent along, but how to authorize that? Maybe the token grants temporary access to the decryption key.

This complicates things because the decryption key is tied to the user's permissions. So when generating the share link, perhaps the backend creates a temporary signed URL that includes the decryption key encrypted in a way that only the token holder can access. But that's getting complicated.

Alternatively, when the share link is accessed, the backend generates a short-lived JWT for the guest user, allowing them to download the file once. But that depends on the implementation.

I think the key points are:

- Use Django and React as per technical requirements.

- Implement MFA with TOTP.

- Encrypt files at rest with AES, decrypt on client side.

- Handle file sharing with expiring links.

- Role-based access control.

Now, considering all these, the assistant should outline the steps to build this application, addressing each requirement with appropriate technologies and design choices, ensuring security best practices are followed.


Step-by-Step Implementation Guide

#### 1. Backend Setup (Django)
**a. Project Initialization**
- Create a Django project and apps for `users`, `files`, and `sharing`.
- Install dependencies:
  ```bash
  pip install django djangorestframework djangorestframework-simplejwt pyotp celery cryptography
  ```

**b. Custom User Model**
- Extend `AbstractUser` to include roles and MFA secrets:
  ```python
  # users/models.py
  from django.contrib.auth.models import AbstractUser

  class CustomUser(AbstractUser):
      ROLES = (('SUPERADMIN', 'SuperAdmin'), ('USER', 'User'), ('GUEST', 'Guest'))
      role = models.CharField(max_length=20, choices=ROLES, default='USER')
      mfa_secret = models.CharField(max_length=255, null=True, blank=True)
  ```

**c. JWT Authentication**
- Configure `djangorestframework-simplejwt` in `settings.py`:
  ```python
  REST_FRAMEWORK = {
      'DEFAULT_AUTHENTICATION_CLASSES': (
          'rest_framework_simplejwt.authentication.JWTAuthentication',
      )
  }
  ```

**d. MFA Integration**
- Use `pyotp` to generate and verify TOTP codes:
  ```python
  # users/utils.py
  import pyotp

  def generate_mfa_secret():
      return pyotp.random_base32()

  def get_mfa_uri(user):
      return pyotp.totp.TOTP(user.mfa_secret).provisioning_uri(user.email, issuer_name="SecureFileApp")
  ```

#### 2. File Encryption & Queue
**a. File Model**
- Store encrypted files and their metadata:
  ```python
  # files/models.py
  class File(models.Model):
      owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
      encrypted_data = models.BinaryField()
      encryption_key = models.BinaryField()  # Encrypted with server's public key
      iv = models.BinaryField()
      uploaded_at = models.DateTimeField(auto_now_add=True)
  ```

**b. Celery Task for Encryption**
- Process uploads asynchronously:
  ```python
  # files/tasks.py
  from celery import shared_task
  from cryptography.fernet import Fernet

  @shared_task
  def encrypt_file(file_id):
      file = File.objects.get(id=file_id)
      # Encryption logic here (simplified)
      key = Fernet.generate_key()
      cipher = Fernet(key)
      encrypted_data = cipher.encrypt(file.temp_data)
      file.encrypted_data = encrypted_data
      file.save()
  ```

#### 3. File Sharing & RBAC
**a. ShareLink Model**
- Track permissions and expiration:
  ```python
  # sharing/models.py
  class ShareLink(models.Model):
      file = models.ForeignKey(File, on_delete=models.CASCADE)
      token = models.UUIDField(default=uuid.uuid4, unique=True)
      permissions = models.CharField(max_length=10, choices=(('VIEW', 'View'), ('DOWNLOAD', 'Download')))
      expires_at = models.DateTimeField()
      created_by = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
  ```

**b. Permission Decorators**
- Implement role-based access control:
  ```python
  # files/decorators.py
  from functools import wraps
  from rest_framework.exceptions import PermissionDenied

  def superadmin_required(view_func):
      @wraps(view_func)
      def _wrapped_view(request, *args, **kwargs):
          if not request.user.role == 'SUPERADMIN':
              raise PermissionDenied()
          return view_func(request, *args, **kwargs)
      return _wrapped_view
  ```

#### 4. Frontend (React + TypeScript)
**a. Login with MFA Flow**
- Handle JWT and MFA verification:
  ```tsx
  // Login.tsx
  const handleLogin = async (credentials: { email: string, password: string }) => {
      const res = await axios.post('/api/login/', credentials);
      if (res.data.mfa_required) {
          setMfaUserId(res.data.user_id);
          setShowMfa(true);
      }
  };

  const verifyMfa = async (code: string) => {
      await axios.post('/api/mfa-verify/', { user_id: mfaUserId, code });
      // Store JWT tokens
  };
  ```

**b. File Upload Component**
- Encrypt client-side before upload (optional) or rely on server encryption:
  ```tsx
  // FileUpload.tsx
  const uploadFile = async (file: File) => {
      const formData = new FormData();
      formData.append('file', file);
      await axios.post('/api/upload/', formData);
  };
  ```

**c. Share Link Generation**
- Create time-limited sharing URLs:
  ```tsx
  // ShareDialog.tsx
  const createShareLink = async (fileId: string, permissions: string) => {
      const res = await axios.post('/api/share/', { file_id: fileId, permissions });
      setShareUrl(`${window.location.origin}/share/${res.data.token}`);
  };
  ```

### Security Implementation Checklist

1. **Data in Motion**
   - Enforce HTTPS with TLS 1.3.
   - Use HSTS headers and secure cookies.

2. **Credential Storage**
   - Django's `AbstractUser` uses PBKDF2 hashing by default.
   - Never store plaintext keys.

3. **Key Management**
   - Use AWS KMS or HashiCorp Vault for encryption keys.
   - Encrypt database fields containing keys.

4. **Access Control**
   - Validate permissions on every API request.
   - Use Django's permission classes and decorators.

5. **Session Security**
   - Store JWTs in `httpOnly` cookies.
   - Implement CSRF protection.

6. **Logging & Monitoring**
   - Log all authentication attempts.
   - Monitor for brute-force attacks.

### Infrastructure Diagram

```
Client (React)
  │
  │ HTTPS
  ▼
Django API (Gunicorn)
  │
  ├── PostgreSQL (Users, Files, ShareLinks)
  ├── Redis (Celery Broker)
  ├── Celery Workers (Encryption Tasks)
  └── AWS S3 (Encrypted File Storage)
```

### Testing Strategy

1. **Unit Tests**
   - Verify RBAC rules.
   - Test encryption/decryption cycles.

2. **Integration Tests**
   - Full file upload/download flow with MFA.
   - Share link expiration validation.

3. **Security Tests**
   - OWASP ZAP scans for vulnerabilities.
   - Check for proper JWT invalidation on logout.

This implementation provides a robust foundation for secure file sharing while adhering to modern security practices. All cryptographic operations should be reviewed by a security professional before production deployment.

