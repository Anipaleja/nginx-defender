# Web server configuration
echo "Starting Web Server on port 8080..."

npm init -y
npm install express

cat <<EOF > server.js
const express = require('express');
const app = express();
const port = 8080;

app.get('/', (req, res) => {
  res.send('nginx-defender Web Interface');
});

app.listen(port, () => {
  console.log(`Web Interface running at http://localhost:${port}`);
});
EOF

node server.js

