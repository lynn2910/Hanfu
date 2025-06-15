const {readFileSync} = require("fs");
const path = require("path");
const crypto = require('node:crypto');

const TOKEN = "Bearer " + process.argv[2];

function generate_iv() {
    const ivBytes = crypto.randomBytes(16);
    return ivBytes.toString('hex');
}

const CHUNK_SIZE = 10 * 1024;

async function run() {
    const image = readFileSync(path.join(__dirname, "file_upload_test.png"));
    const fileName = "file_upload_test.png";

    const iv = generate_iv();
    console.log('IV généré :', iv);

    const hash = crypto.createHash('sha256');
    hash.update(image);
    const fileHash = hash.digest('hex');
    console.log('SHA256 du fichier original calculé (pour la finalisation) :', fileHash);


    let session;
    try {
        const initiateResponse = await fetch("http://localhost:8000/upload/initiate", {
            method: "POST",
            body: JSON.stringify({
                path: fileName,
                total_size: image.length,
                iv,
            }),
            headers: {
                "Authorization": TOKEN,
                "Content-Type": "application/json"
            }
        });

        if (!initiateResponse.ok) {
            const errorText = await initiateResponse.text();
            throw new Error(`Erreur lors de l'initialisation de l'upload: ${initiateResponse.status} ${initiateResponse.statusText} - ${errorText}`);
        }

        session = await initiateResponse.json();
        console.log("Session initiée avec succès : ", session);
    } catch (err) {
        console.error("Erreur lors de l'initialisation de l'upload :", err);
        process.exit(1);
    }

    if (!session || !session.session_id) {
        console.error("La session n'a pas été initiée correctement ou l'ID de session est manquant.");
        process.exit(1);
    }

    let totalSent = 0;

    for (let offset_start = 0; offset_start < image.length; offset_start += CHUNK_SIZE) {
        // if (offset_start !== 0) return;

        const offset_end = Math.min(offset_start + CHUNK_SIZE, image.length);
        const chunk = image.slice(offset_start, offset_end);
        totalSent += (offset_end - offset_start);

        const contentRange = `${offset_start}-${offset_end - 1}/${image.length}`;

        console.log(`Envoi du chunk : ${contentRange}`);

        try {
            const chunkResponse = await fetch(`http://localhost:8000/upload/session/${session.session_id}/chunk`, {
                method: "PUT",
                body: chunk,
                headers: {
                    "Authorization": TOKEN,
                    "Content-Range": contentRange,
                    "Content-Type": "application/octet-stream"
                }
            });

            if (!chunkResponse.ok) {
                const errorText = await chunkResponse.text();
                throw new Error(`Erreur lors de l'envoi du chunk ${contentRange}: ${chunkResponse.status} ${chunkResponse.statusText} - ${errorText}`);
            }

            console.log(`Chunk ${contentRange} envoyé avec succès.`);
        } catch (err) {
            console.error("Erreur lors de l'envoi d'un chunk :", err);
            process.exit(1);
        }
    }

    console.log("Envoyés: ", totalSent)

    console.log("Tous les chunks ont été envoyés. L'upload est terminé côté client.");

    // return;

    try {
        const finalizeResponse = await fetch(`http://localhost:8000/upload/session/${session.session_id}/finalize`, {
            method: "POST",
            body: JSON.stringify({
                file_hash: fileHash,
            }),
            headers: {
                "Authorization": TOKEN,
                "Content-Type": "application/json"
            }
        });

        if (!finalizeResponse.ok) {
            const errorText = await finalizeResponse.text();
            throw new Error(`Erreur lors de la finalisation de l'upload: ${finalizeResponse.status} ${finalizeResponse.statusText} - ${errorText}`);
        }

        const finalizeResult = await finalizeResponse.json();
        console.log("Finalisation terminée : ", finalizeResult);
    } catch (err) {
        console.error("Erreur lors de la finalisation de l'upload :", err);
        process.exit(1);
    }
}

run();