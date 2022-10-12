import { TrueNas } from './truenas'
import fs from 'fs';
import { spawn } from 'child_process';

function openssl(params: string[]): Promise<{data: Buffer, error: Buffer}> {
    return new Promise((resolve, reject) => {
        const stdout: Buffer[] = [];
        const stderr: Buffer[] = [];

        const openSSLProcess = spawn('openssl', params);

        openSSLProcess.stdout.on('data', (data: Buffer) => {
            stdout.push(data);
        });
    
        openSSLProcess.stderr.on('data', (data: Buffer) => {
            stderr.push(data);
        });
    
        openSSLProcess.on('close', (code) => {
            if (code != 0) {
                reject(new Error(Buffer.concat(stderr).toString()));
            }
            resolve({data: Buffer.concat(stdout), error: Buffer.concat(stderr)});
        });
    });
}

export async function convertCsr(cert: TrueNas.Cert): Promise<string | null> {
    const dir = await fs.promises.mkdtemp('/tmp/tnscm');
    let csr: string | null = null;
    try {
        const certpath = dir + '/a';
        const keypath = dir + '/b'; //TODO use stdin instead
        await fs.promises.writeFile(certpath, cert.certificate);
        await fs.promises.writeFile(keypath, cert.privatekey);
        const result = await openssl(['x509', '-x509toreq', '-in', certpath, '-signkey', keypath]);
        csr = result.data.toString();
    } catch (e: any) {
        console.log(e);
    } finally {
        await fs.promises.rm(dir, {recursive: true});
    }
    return csr;
}
