import express, { Express, Request, Response } from "express";
import { readFileSync } from "fs";
import { TrueNas } from "./truenas";
import { convertPkcs12 } from "./util"

const config: {
    server_port: number;
    truenas_url: string;
    truenas_api_key: string;
    cert_lifetime_days: number;
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
    try {
        const cert = await truenas.getCertByFingerprint(<string> fingerprint);

        let result = `
        <b>${cert.name}</b><br/>
        SHA1 fingerprint: ${cert.fingerprint}<br/>
        Until: ${cert.until}<br/>
        Remaining: ${Math.floor(TrueNas.certRemainingDays(cert))} days<br/>
        <form action="/renew" method="post"><button>Renew</button></form>`;

        const allCerts = await truenas.getAllCert();
        const matchingCerts = allCerts.filter(c => c.DN == cert.DN);
        if (matchingCerts.length > 0) {
            result += 'Matching certs:<ul>'
            for (const c of matchingCerts) {
                result += `<li><a href="/pkcs12/${c.id}">${c.name}</a></li>`;
            }
            result += '</ul>';
        }
        res.send(result);
    } catch (e) {
        res.status(500);
        if (e instanceof Error) {
            res.send((<Error> e).message);
        }
    }
});

app.get('/pkcs12/:certId',async (req: Request, res: Response) => {
    const fingerprint = req.header('X-SSL-Client-SHA1');
    const clientCert = await truenas.getCertByFingerprint(<string> fingerprint);
    const cert = await truenas.getCertById(parseInt(req.params.certId));
    if (!cert) {
        res.sendStatus(404);
        return;
    }
    if (cert.DN != clientCert.DN) {
        // don't let our users get the privkeys of other users
        res.sendStatus(403);
        return;
    }

    const pkcs12 = await convertPkcs12(cert);
    if (!pkcs12) {
        res.sendStatus(500);
        return;
    }

    res.contentType('application/x-pkcs12');
    res.setHeader('Content-disposition', `attachment; filename=${cert.name}.pfx`);
    res.send(pkcs12);
});

app.post('/renew', async (req: Request, res: Response) => {
    const fingerprint = req.header('X-SSL-Client-SHA1');
    const cert = await truenas.getCertByFingerprint(<string> fingerprint);

    const newCert = await truenas.renewCert(cert, config.cert_lifetime_days);
    res.redirect(`/pkcs12/${newCert.id}`);
});

app.listen(config.server_port);
