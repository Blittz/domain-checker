import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

APP_PASSWORD = os.environ.get("DOMAINCHECKER_PASSWORD", "")
COOKIE_NAME = "dc_auth"

app = FastAPI()


def authed(request: Request) -> bool:
    return request.cookies.get(COOKIE_NAME) == "ok"


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if APP_PASSWORD and not authed(request):
        return HTMLResponse(
            """
            <html>
              <head><title>Domain Checker Login</title></head>
              <body style="font-family: sans-serif; max-width: 520px; margin: 60px auto;">
                <h2>Domain Checker</h2>
                <p>Please enter the password to continue.</p>
                <form method="post" action="/login">
                  <input type="password" name="password" style="width: 100%; padding: 10px; font-size: 16px;" autofocus />
                  <button style="margin-top: 12px; padding: 10px 16px; font-size: 16px;">Login</button>
                </form>
              </body>
            </html>
            """,
            status_code=401,
        )

    return HTMLResponse(
        """
        <html>
          <head><title>Domain Checker</title></head>
          <body style="font-family: sans-serif; max-width: 900px; margin: 40px auto; line-height: 1.4;">
            <h1>Domain Checker</h1>
            <p>? FastAPI is running behind your Cloudflare Tunnel.</p>
            <p>Next step: build the bulk DNS + redirect checker UI.</p>
          </body>
        </html>
        """
    )


@app.post("/login")
async def login(password: str = Form(...)):
    if not APP_PASSWORD:
        return RedirectResponse("/", status_code=303)

    if password != APP_PASSWORD:
        return HTMLResponse("Wrong password.", status_code=401)

    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        COOKIE_NAME,
        "ok",
        httponly=True,
        secure=True,       # safe because users access via HTTPS
        samesite="strict",
        max_age=60 * 60 * 24,
    )
    return resp


@app.post("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp
