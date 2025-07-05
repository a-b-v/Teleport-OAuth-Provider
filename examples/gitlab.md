## 🔧 GitLab Setup to Authenticate via Teleport using OIDC Bridge

This guide explains how to configure GitLab to authenticate users using **Teleport** as an identity provider via the **OIDC Bridge**.

### ⚠️ Important Requirements

* GitLab **requires HTTPS** for OIDC.
* Therefore, the `oidc-bridge` **must be exposed directly over HTTPS**, **without going through Teleport**.

---

### 🌐 Component Addresses

* **OIDC Bridge (publicly accessible)**: `https://oidc-bridge.example.com`
* **GitLab Web Interface**: `https://gitlab.teleport.example.com`

---

### 🛠️ GitLab Configuration (`gitlab.rb`)

Update your `gitlab.rb` configuration file with the following `omniauth_providers` block:

```ruby
gitlab_rails['omniauth_providers'] = [
  {
    name: 'openid_connect',
    label: "Teleport login",
    args: {
      name: "openid_connect",
      scope: ["openid", "profile", "email"],
      response_type: "code",
      issuer: "https://oidc-bridge.example.com",
      client_auth_method: "query",
      discovery: true,
      uid_field: "sub",
      pkce: true,
      client_options: {
        identifier: "gitlab",
        secret: "none",
        redirect_uri: "https://gitlab.teleport.example.com/users/auth/openid_connect/callback"
      }
    }
  }
]
```

---

### ✅ Final Steps

1. **Reconfigure GitLab** to apply the changes:

   ```bash
   sudo gitlab-ctl reconfigure
   ```

2. **Test login** from the GitLab UI using the “Teleport login” button.

