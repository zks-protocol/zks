@echo off
echo Deploying ZKS Protocol Signaling Server...
cd cloudflare-workers\signaling-server
call npm install
call npx wrangler deploy
echo Deployment command finished.
pause
