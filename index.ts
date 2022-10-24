import express, { Express, Request, Response } from "express";
import { readFileSync } from "fs";
import { TrueNas } from "./truenas";
import { convertCsr } from "./util"

const config: {
    server_port: number;
    truenas_url: string;
    truenas_api_key: string;
} = JSON.parse(readFileSync('./config.json').toString());

const truenas: TrueNas.Connector = new TrueNas.Connector(config.truenas_url, config.truenas_api_key);
const app: Express = express();

app.get('/', async (req: Request, res: Response) => {
    let html = '<table><tbody><tr><th>Name</th><th>Valid</th><th>Fingerprint</th></tr>';
    const ca = await truenas.getAllCa();
    for (const i of ca) {
        html += `<tr><td>${i.name}</td><td>${i.from} - ${i.until}</td><td>${i.fingerprint}</td></tr>`;
    }
    html += '</tbody></table><br/>';
    html += '<a href="/me">My cert</a>';
    res.send(html);
});

app.get('/me', async (req: Request, res: Response) => {
    const fingerprint = req.header('X-SSL-Client-SHA1');
    const cert = await truenas.getCertByFingerprint(<string> fingerprint);

    let result = `
    <b>${cert.name}</b><br/>
    SHA1 fingerprint: ${cert.fingerprint}<br/>
    Until: ${cert.until}<br/>
    Remaining: ${Math.floor(TrueNas.certRemainingDays(cert))} days<br/>
    <form action="/renew" method="post"><button>Renew</button></form>`;

    const allCerts = await truenas.getAllCert();
    const matchingCerts = allCerts.filter(c => c.DN == cert.DN && c.id != cert.id);
    if (matchingCerts.length > 0) {
        result += 'Matching certs:<ul>'
        for (const c of matchingCerts) {
            result += `<li>${c.name}</li>`;
        }
        result += '</ul>';
    }
    res.send(result);
});

app.post('/renew', async (req: Request, res: Response) => {
    const fingerprint = req.header('X-SSL-Client-SHA1');
    const cert = await truenas.getCertByFingerprint(<string> fingerprint);

    const csr = await convertCsr(cert);
    if (!csr) {
        res.status(500).send("CSR conversion failed");
        return;
    }

    let importedCsr: TrueNas.Cert | null = null;
    try {
        importedCsr = await truenas.importCsr(csr, cert);
    } catch (e: any) {
        res.status(500).send(e.toString());
    }

    if (!importedCsr) {
        res.status(500).send("CSR upload failed");
        return;
    }

    const signed = await truenas.signCsr(importedCsr.id, cert.signedby.id, importedCsr.name + '_signed');

    res.contentType('json');
    res.send(JSON.stringify(signed, undefined, 4));
});

app.listen(config.server_port);
