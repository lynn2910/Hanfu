const {readFileSync} = require("fs");
const path = require("path");
const crypto = require('node:crypto');

const TOKEN = "Bearer " + process.argv[2];

function generate_iv() {
    const ivBytes = crypto.randomBytes(16);
    return ivBytes.toString('hex');
}

async function run() {
    const image = readFileSync(path.join(__dirname, "file_upload_test.png"));

    const iv = generate_iv();
    console.log('IV :', iv);

    let session;
    await fetch("http://localhost:8000/upload/initiate", {
        method: "POST",
        body: JSON.stringify({
            file_name: "file_upload_test.png",
            total_size: image.length,
            iv,
        }),
        headers: {
            "Authorization": TOKEN
        }
    })
        .then((res) => res.json())
        .then(data => {
            session = data;
        })
        .catch(err => {
            console.error(err);
            process.exit(1);
        });

    console.log("Session : ", session);
}

run()