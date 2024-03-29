import axios from "axios";

/**
 * TrueNAS API v2 wrapper
 */
export namespace TrueNas {

export interface Cert {
    id: number,
    type: number,
    name: string,
    email: string,
    san: string[],
    certificate: string,
    privatekey: string,
    /// SHA1 sum, uppercase, separated by ':'
    fingerprint: string,
    from: string,
    until: string,
    key_length: number,
    key_type: 'RSA',
    city: string,
    common: string,
    country: string,
    state: string,
    organization: string,
    digest_algorithm: 'SHA512',
    signedby: {
        id: number,
        certificate: string,
        name: string,
        privatekey: string,
        signed_certificates: number,
        from: string,
        until: string
    },
    DN: string
    // not all fields and enum values are declared
};

export interface CertificateCreateParams {
    create_type: 'CERTIFICATE_CREATE_INTERNAL' | 'CERTIFICATE_CREATE_IMPORTED' | 'CERTIFICATE_CREATE_CSR' | 'CERTIFICATE_CREATE_IMPORTED_CSR' | 'CERTIFICATE_CREATE_ACME',
    name: string,
    type: number,
    key_length: number,
    key_type: 'RSA',
    lifetime: number,
    city: string,
    common: string,
    country: string,
    email: string,
    organization: string,
    state: string,
    digest_algorithm: 'SHA512',
    signedby: number,
    san: string[],
    cert_extensions?: {
        BasicConstraints?: {
            enabled: boolean,
            ca?: boolean,
            path_length?: number | null,
            extension_critical?: boolean
        },
        AuthorityKeyIdentifier?: {
            enabled: boolean,
            authority_cert_issuer?: boolean,
            extension_critical?: boolean
        },
        ExtendedKeyUsage?: {
            enabled: boolean,
            usages?: string[],
            extension_critical?: boolean
        },
        KeyUsage?: {
            enabled: boolean,
            digital_signature?: boolean,
            content_commitment?: boolean,
            key_encipherment?: boolean,
            data_encipherment?: boolean,
            key_agreement?: boolean,
            key_cert_sign?: boolean,
            crl_sign?: boolean,
            encipher_only?: boolean,
            decipher_only?: boolean,
            extension_critical?: boolean
        }
    }
};

export function certRemainingDays(cert: Cert): number {
    const end = new Date(cert.until);
    const now = new Date();
    return (+end - +now) / (24 * 3600e3);
}

var certByFingerprintCache: Map<string, Cert> = new Map();

export class Connector {
    server_url: string;
    api_key: string;

    constructor(server_url: string, api_key: string) {
        this.server_url = server_url;
        this.api_key = api_key;
    }

    get api(): string {
        return this.server_url + 'api/v2.0';
    }

    get auth(): NodeJS.Dict<string> {
        return {'Authorization': 'Bearer ' + this.api_key};
    }

    async getAllCa(): Promise<{
        id: number,
        type: number,
        name: string,
        email: string,
        DN: string,
        fingerprint: string,
        certificate: string,
        from: string,
        until: string
        // not all fields are declared
    }[]> {
        const resp = await axios.get(this.api + '/certificateauthority', {
            headers: this.auth
        })
        return resp.data;
    }

    async getAllCert(): Promise<Cert[]> {
        const resp = await axios.get(this.api + '/certificate', {
            headers: this.auth
        })
        return resp.data;
    }

    /**
     * @param fingerprint SHA1 sum fingerprint of cert, lowercase, no separators
     * @throws Error when the certificate is not found
     */
     async getCertByFingerprint(fingerprint: string): Promise<Cert> {
        if (certByFingerprintCache.has(fingerprint)) {
            return <Cert> certByFingerprintCache.get(fingerprint);
        }

        const certs = await this.getAllCert();
        const myCert = certs.find((value) => {
            return value.fingerprint.toLowerCase().replace(/:/g, '') == fingerprint;
        });
        if (myCert) {
            certByFingerprintCache.set(fingerprint, myCert);
            return myCert;
        }
        throw new Error('Fingerprint not found');
    }

    /**
     * @param id unique identifier of cert
     * @throws Error when the certificate is not found
     */
    async getCertById(id: number): Promise<Cert> {
        const certs = await this.getAllCert();
        const myCert = certs.find((value) => {
            return value.id == id;
        });
        if (myCert) {
            return myCert;
        }
        throw new Error('ID not found');
    }

    /**
     * increments a counter at the end of the certificate name
     * @param oldName old certificate name that is being renewed
     * @returns the new name, e.g 'ASD_5' for input 'ASD_4'
     */
    static generateName(oldName: string): string {
        let parts = oldName.split('_');
        let counter = 0;
        if (parts[parts.length-1].match(/[0-9]+/)) {
            counter = parseInt(<string> parts.pop());
        }
        counter++;

        return parts.join('_') + '_' + counter;
    }

    // TODO should move to an application layer from connector
    async renewCert(cert: Cert, lifetimeDays: number): Promise<Cert> {
        let req_data: CertificateCreateParams = {
            create_type: 'CERTIFICATE_CREATE_INTERNAL',
            name: Connector.generateName(cert.name),
            type: cert.type,
            key_length: cert.key_length,
            key_type: cert.key_type,
            lifetime: lifetimeDays,
            city: cert.city,
            common: cert.common,
            country: cert.country,
            email: cert.email,
            organization: cert.organization,
            state: cert.state,
            digest_algorithm: cert.digest_algorithm,
            signedby: cert.signedby.id,
            san: cert.san.map(s => s.replace(/^DNS:/, '')), // 'DNS:' prefix has to be stripped
            cert_extensions: {
                BasicConstraints: {
                  ca: false,
                  enabled: true,
                  extension_critical: true
                },
                AuthorityKeyIdentifier: {
                  authority_cert_issuer: true,
                  enabled: true,
                  extension_critical: false
                },
                ExtendedKeyUsage: {
                  usages: [
                      'CLIENT_AUTH'
                  ],
                  enabled: true,
                  extension_critical: true
                },
                KeyUsage: {
                  enabled: true,
                  digital_signature: true,
                  key_agreement: true,
                  extension_critical: true
                }
            }
        };

        const resp = await axios.post(this.api + '/certificate', req_data, {headers: this.auth});
        const jobId = resp.data;

        return await this.waitJobDone(jobId);
    }

    async waitJobDone(jobId: number): Promise<Cert> {
        // I mean they could have added a 'wait-for' option to the API...
        while (true) {
            const get_jobs = await axios.get(this.api + '/core/get_jobs', {headers: this.auth});
            if (get_jobs.status != 200) {
                throw Error('Failed to get job list');
            }
            const jobs_status: {
                id: number,
                method: string,
                state: 'SUCCESS' | 'RUNNING' | 'FAILED',
                error: string | null,
                exception: string | null,
                result?: Cert
            }[] = get_jobs.data;

            const job = jobs_status.find((job) => {
                return job.id == jobId
            });

            if (!job) {
                throw Error(`Job #${jobId} not found`);
            }

            if (job.state == 'RUNNING') {
                continue;
            }

            if (job.state == 'FAILED') {
                throw Error(`Error creating cert: ${job.error}`);
            }
            if (job.state == 'SUCCESS') {
                return <Cert> job.result;
            }

            throw Error(`Invalid job state: ${job.state}`);
        }
    }

    async importCsr(csr: string, cert: Cert): Promise<Cert> {
        let req_data = {
            create_type: 'CERTIFICATE_CREATE_IMPORTED_CSR',
            name: Connector.generateName(cert.name) + '_CSR',
            CSR: csr,
            privatekey: cert.privatekey
        };

        const resp = await axios.post(this.api + '/certificate', req_data, {headers: this.auth});
        const jobId = resp.data;

        return await this.waitJobDone(jobId);
    }

    async signCsr(csrId: number, caId: number, name: string): Promise<Cert|null> {
        const req_data = {
            ca_id: caId,
            csr_cert_id: csrId,
            name: name,
            cert_extensions: {
              BasicConstraints: {
                ca: false,
                enabled: true,
                extension_critical: true
              },
              AuthorityKeyIdentifier: {
                authority_cert_issuer: true,
                enabled: true,
                extension_critical: false
              },
              ExtendedKeyUsage: {
                usages: [
                    'CLIENT_AUTH'
                ],
                enabled: true,
                extension_critical: true
              },
              KeyUsage: {
                enabled: true,
                digital_signature: true,
                key_agreement: true,
                extension_critical: true
              }
            }
        };
        const resp = await axios.post(this.api + '/certificateauthority/ca_sign_csr', req_data, {headers: this.auth});

        if (resp.status == 200) {
            return resp.data;
        }

        return null;
    }
};

}
