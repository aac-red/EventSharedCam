# Upload page

Files to publish on GitHub Pages: index.html, uploader.js, credcrypto.js, credential.enc.json
Never publish: service-account.json

1. On your computer (Node 18+), in this folder:
   node encrypt-credential.js service-account.json --folder <EVENT_FOLDER_ID>
   It writes credential.enc.json and prints the event code once.
2. Publish the four files. Guest link: https://<username>.github.io/<repo>/?event=<CODE>
3. Changing the code = run step 1 again and republish credential.enc.json.
