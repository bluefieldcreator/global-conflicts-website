import { NextApiRequest, NextApiResponse } from 'next';
import { getSession, Session } from 'next-auth/react';

export enum CREDENTIAL {
    ANY = 'ANY',
    NEW_GUY = 'New Guy',
    MEMBER = 'Member',
    MISSION_MAKER = 'Mission Maker',
    MISSION_REVIEWER = 'Mission Review Team',
    MISSION_ADMINISTRATOR = 'Mission Administrator',
    GM = 'Arma GM',
    ADMIN = 'Admin',
}

interface UserRole {
    name: string;
}

interface ExtendedSession extends Session {
    user: {
        roles: UserRole[];
        isAdmin?: boolean;
    };
}

interface ExtendedRequest extends NextApiRequest {
    session?: ExtendedSession;
    isAdmin?: boolean;
}

type NextFunction = () => void | Promise<void>;
type ValidationResult = Promise<ExtendedSession['user'] | void>;

/**
 * Checks if a user has admin privileges
 */
const isAdmin = (roles: UserRole[]): boolean => {
    return roles.some(role => role.name === CREDENTIAL.ADMIN);
};

/**
 * Checks if a user has a specific credential
 */
const hasCredential = (roles: UserRole[], cred: CREDENTIAL): boolean => {
    return roles.some(role => role.name === cred);
};

/**
 * Handles successful authentication
 */
const handleSuccess = (
    req: ExtendedRequest,
    session: ExtendedSession,
    hasAdminRole: boolean,
    next?: NextFunction
): ValidationResult => {
    if (next) {
        if (hasAdminRole) {
            session.user.isAdmin = true;
            req.isAdmin = true;
        }
        req.session = session;
        return Promise.resolve(next());
    }
    return Promise.resolve(session.user);
};

/**
 * Validates a single credential
 */
export async function validateUser(
    req: ExtendedRequest,
    res: NextApiResponse,
    cred: CREDENTIAL,
    next?: NextFunction
): ValidationResult {
    try {
        const session = await getSession({ req }) as ExtendedSession;
        
        if (!session) {
            throw new Error('Unauthorized');
        }

        if (cred === CREDENTIAL.ANY) {
            return handleSuccess(req, session, false, next);
        }

        const hasAdminRole = isAdmin(session.user.roles);
        if (hasAdminRole) {
            return handleSuccess(req, session, true, next);
        }

        if (hasCredential(session.user.roles, cred)) {
            return handleSuccess(req, session, false, next);
        }

        throw new Error('Not Authorized');
    } catch (error) {
        if (error.message === 'Unauthorized') {
            return Promise.reject(401);
        }
        return Promise.reject({ message: error.message });
    }
}

/**
 * Validates multiple credentials
 */
export async function validateUserList(
    req: ExtendedRequest,
    res: NextApiResponse,
    credList: CREDENTIAL[],
    next?: NextFunction
): ValidationResult {
    try {
        const session = await getSession({ req }) as ExtendedSession;
        
        if (!session) {
            throw new Error('Unauthorized');
        }

        if (credList.includes(CREDENTIAL.ANY)) {
            return handleSuccess(req, session, false, next);
        }

        const hasAdminRole = isAdmin(session.user.roles);
        if (hasAdminRole) {
            return handleSuccess(req, session, true, next);
        }

        const hasAnyRequiredCredential = session.user.roles.some(role => 
            credList.includes(role.name as CREDENTIAL)
        );

        if (hasAnyRequiredCredential) {
            return handleSuccess(req, session, false, next);
        }

        throw new Error('Not Authorized');
    } catch (error) {
        if (error.message === 'Unauthorized') {
            return Promise.reject(401);
        }
        return Promise.reject({ message: error.message });
    }
}
