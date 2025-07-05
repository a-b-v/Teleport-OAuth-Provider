## 🔧 MinIO Setup to Authenticate via Teleport using OIDC Bridge

This setup enables MinIO to authenticate users through **Teleport** using an **OIDC bridge**.

### 🌐 Component Addresses

* **OIDC Bridge URL**: `http://oidc-bridge.internal`
* **MinIO Console URL (through Teleport)**: `https://minio.teleport.example.com`

### 🛠️ Required Environment Variables

Set the following environment variables in the MinIO configuration to enable OIDC authentication:

```bash

MINIO_IDENTITY_OPENID_CONFIG_URL_PRIMARY_IAM="http://oidc-bridge.internal/.well-known/openid-configuration"
MINIO_IDENTITY_OPENID_CLIENT_ID_PRIMARY_IAM="minio"
MINIO_IDENTITY_OPENID_CLIENT_SECRET_PRIMARY_IAM="none"
MINIO_IDENTITY_OPENID_DISPLAY_NAME_PRIMARY_IAM="Teleport"
MINIO_IDENTITY_OPENID_CLAIM_NAME_PRIMARY_IAM=policy
MINIO_IDENTITY_OPENID_REDIRECT_URI_PRIMARY_IAM=https://minio.teleport.example.com/oauth_callback

```

### 📝 Notes

* `MINIO_IDENTITY_OPENID_CONFIG_URL_PRIMARY_IAM` points to the discovery document of your OIDC bridge.
* The `CLAIM_NAME` is used to extract policy information from the token (e.g., `policy` claim).
* The `REDIRECT_URI` must match what is registered with your OIDC provider, typically routed through Teleport.


In **Teleport**, you need to create roles in the format `minio:bucket_access`, where:

* `minio` corresponds to the value of `CLIENT_ID_PRIMARY_IAM`
* `bucket_access` is the name of the MinIO policy that defines access permissions to specific buckets.

When a user authenticates, MinIO will assign policies based on the roles associated with that user.

