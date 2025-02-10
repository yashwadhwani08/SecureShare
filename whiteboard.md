

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

