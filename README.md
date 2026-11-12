# آپلودر شخصی

## اجرا روی Railway
1. پروژه رو روی GitHub بذار → Railway → New Project → Deploy from GitHub
2. توی سرویس: Settings → Volumes → Add Volume → Mount path: `/data`
3. Variables: `DATA_DIR=/data`  (اختیاری: `PASSWORD=E123`)
4. Settings → Networking → Generate Domain
