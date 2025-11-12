# 🔐 Oauth2_for_Google_in_FastAPI

A lightweight, production-ready helper library for integrating **Google OAuth2** authentication into **FastAPI** applications — with secure cookies, async/await compatibility, and a one-line-per-route setup.

This helper simplifies Google login by managing the entire OAuth2 flow for you:
authorization, token exchange, user info retrieval, and session handling.

---

## 🚀 Features

- ✅ Plug-and-play Google OAuth2 integration  
- ⚡ 100% Async/Await supported  
- 🔒 Secure cookie-based session handling  
- 🧠 Dependency injection for `google_user()`  
- 🎯 One-line protected, optional, and admin routes  
- 🧩 Ready for both web apps & API backends  
- 🧰 Minimal config, clean syntax  

---

| Security Feature | Description                                         |
| ---------------- | --------------------------------------------------- |
| `app_secret_key` | Used for cookie signing — must be ≥ 32 random chars |
| Cookies          | `HttpOnly`, `Secure`, `SameSite` enabled            |
| Token Exchange   | Done server-side, not exposed to frontend           |
| HTTPS Required   | Always use HTTPS in production                      |
| Refresh Token    | (Planned feature for longer sessions)               |


Step	Function	Purpose
🧩 1	setup_google_auth(config)	Initialize Google OAuth client
🔗 2	login_redirect(request)	Redirect user to Google for login
🔁 3	handle_callback(request)	Handle Google’s OAuth2 callback
👤 4	google_user()	Get the logged-in user (dependency)






