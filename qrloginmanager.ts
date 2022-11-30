export namespace QrLoginManager {

interface Session {
    key: string;
    certId: number;
    endOfLife: number;
};

const SESSION_LIFETIME_SEC = 60;

let sessions: Session[] = [];

export function getKey(certId: number): string {
    let session: Session|null = null;

    sessions.forEach((value, index, object) => {
        if (value.endOfLife <= new Date().getTime()) {
            object.splice(index, 1);
        } else if (value.certId == certId) {
            session = value;
        }
    });

    if (!session) {
        session = {
            key: randomString(40),
            certId: certId,
            endOfLife: new Date().getTime() + SESSION_LIFETIME_SEC * 1000
        };
        sessions.push(session);
    }

    return session.key;
}

export function getUrl(prefix: string, certId: number) {
    return prefix + getKey(certId);
}

export function getCertIdBySession(sessionKey: string): number | null {
    for (const value of sessions) {
        if (value.endOfLife > new Date().getTime()) {
            if (value.key == sessionKey) {
                return value.certId;
            }
        }
    }
    return null;
}

function randomString(length: number) {
    return [...Array(length)].map(() => (Math.floor(Math.random() * 36)).toString(36)).join('');
}

};
