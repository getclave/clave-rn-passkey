import { NotSupportedError } from './PasskeyError';
import { Platform } from 'react-native';
import { PasskeyAndroid } from './PasskeyAndroid';
import { PasskeyiOS } from './PasskeyiOS';

const generateCreateRequest = (
  userId: string,
  userName: string,
  challenge: string,
  options: Partial<CreateOptions>
): PasskeyRegistrationRequest => {
  return {
    challenge,
    rp: {
      id: 'https://getclave.io',
      name: 'Clave',
    },
    user: {
      id: userId,
      name: userName,
      displayName: userName,
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' }, // ES256 (Webauthn's default algorithm)
    ],
    timeout: options.timeout ?? 60000,
    authenticatorSelection: {
      userVerification: options.userVerification ?? 'required', // Webauthn default is "preferred"
      authenticatorAttachment: 'platform',
      residentKey: options.discoverable ?? 'preferred', // official default is 'discouraged'
      requireResidentKey: options.discoverable === 'required', // mainly for backwards compatibility, see https://www.w3.org/TR/webauthn/#dictionary-authenticatorSelection
    },
    attestation: options.attestation ? 'direct' : 'none',
  };
};

const generateSignRequest = (
  credentialIds: Array<string>,
  challenge: string,
  options: Partial<SignOptions>
): PasskeyAuthenticationRequest => {
  return {
    challenge,
    rpId: 'https://getclave.io',
    allowCredentials: credentialIds.map((id) => {
      return {
        id,
        type: 'public-key',
        transports: ['hybrid', 'usb', 'ble', 'nfc'],
      };
    }),
    userVerification: options.userVerification ?? 'required',
    timeout: options.timeout ?? 60000,
  };
};

export class Passkey {
  public static async create(
    userId: string,
    userName: string,
    challenge: string,
    options: Partial<CreateOptions> = {}
  ) {
    if (!Passkey.isSupported) {
      throw NotSupportedError;
    }

    const request = generateCreateRequest(userId, userName, challenge, options);

    if (Platform.OS === 'android') {
      return PasskeyAndroid.register(request);
    }
    return PasskeyiOS.register(request, options.withSecurityKey ?? false);
  }

  /**
   * Creates a new Passkey
   *
   * @param request The FIDO2 Attestation Request in JSON format
   * @param options An object containing options for the registration process
   * @returns The FIDO2 Attestation Result in JSON format
   * @throws
   */
  public static async register(
    request: PasskeyRegistrationRequest,
    { withSecurityKey }: { withSecurityKey: boolean } = {
      withSecurityKey: false,
    }
  ): Promise<PasskeyRegistrationResult> {
    if (!Passkey.isSupported) {
      throw NotSupportedError;
    }

    if (Platform.OS === 'android') {
      return PasskeyAndroid.register(request);
    }
    return PasskeyiOS.register(request, withSecurityKey);
  }

  public static async sign(
    credentialIds: Array<string>,
    challenge: string,
    options: Partial<SignOptions> = {}
  ) {
    if (!Passkey.isSupported) {
      throw NotSupportedError;
    }

    const request = generateSignRequest(credentialIds, challenge, options);

    if (Platform.OS === 'android') {
      return PasskeyAndroid.authenticate(request);
    }
    return PasskeyiOS.authenticate(request, options.withSecurityKey ?? false);
  }

  /**
   * Authenticates using an existing Passkey
   *
   * @param request The FIDO2 Assertion Request in JSON format
   * @param options An object containing options for the authentication process
   * @returns The FIDO2 Assertion Result in JSON format
   * @throws
   */
  public static async authenticate(
    request: PasskeyAuthenticationRequest,
    { withSecurityKey }: { withSecurityKey: boolean } = {
      withSecurityKey: false,
    }
  ): Promise<PasskeyAuthenticationResult> {
    if (!Passkey.isSupported) {
      throw NotSupportedError;
    }

    if (Platform.OS === 'android') {
      return PasskeyAndroid.authenticate(request);
    }
    return PasskeyiOS.authenticate(request, withSecurityKey);
  }

  /**
   * Checks if Passkeys are supported on the current device
   *
   * @returns A boolean indicating whether Passkeys are supported
   */
  public static isSupported(): boolean {
    if (Platform.OS === 'android') {
      return Platform.Version > 28;
    }

    if (Platform.OS === 'ios') {
      return parseInt(Platform.Version, 10) > 15;
    }

    return false;
  }
}

/**
 * The available options for Passkey operations
 */
export interface PasskeyOptions {
  withSecurityKey: boolean; // iOS only
}

// https://www.w3.org/TR/webauthn-2/#dictionary-credential-descriptor
interface PublicKeyCredentialDescriptor {
  type: string;
  id: string;
  transports?: Array<string>;
}

/**
 * The FIDO2 Attestation Request
 * https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
 */
export interface PasskeyRegistrationRequest {
  challenge: string;
  rp: {
    id: string;
    name: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  timeout?: number;
  excludeCredentials?: Array<PublicKeyCredentialDescriptor>;
  authenticatorSelection?: {
    authenticatorAttachment?: string;
    requireResidentKey?: boolean;
    residentKey?: string;
    userVerification?: string;
  };
  attestation?: string;
  extensions?: Record<string, unknown>;
}

/**
 * The FIDO2 Attestation Result
 */
export interface PasskeyRegistrationResult {
  id: string;
  rawId: string;
  type?: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
  };
}

/**
 * The FIDO2 Assertion Request
 * https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
 */
export interface PasskeyAuthenticationRequest {
  challenge: string;
  rpId: string;
  timeout?: number;
  allowCredentials?: Array<PublicKeyCredentialDescriptor>;
  userVerification?: string;
  extensions?: Record<string, unknown>;
}

/**
 * The FIDO2 Assertion Result
 */
export interface PasskeyAuthenticationResult {
  id: string;
  rawId: string;
  type?: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle: string;
  };
}

export interface CommonOptions {
  userVerification: string;
  authenticatorType: 'auto' | 'local' | 'extern' | 'roaming' | 'both';
  timeout: number;
  debug: boolean;
}

export interface CreateOptions extends CommonOptions {
  userHandle: string;
  attestation: boolean;
  discoverable: string;
  withSecurityKey: boolean;
}

export interface SignOptions extends CommonOptions {
  mediation: 'optional' | 'conditional' | 'required' | 'silent';
  withSecurityKey: boolean;
}
