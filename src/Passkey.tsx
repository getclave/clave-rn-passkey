import { NotSupportedError } from './PasskeyError';
import { Platform } from 'react-native';
import { PasskeyAndroid } from './PasskeyAndroid';
import { PasskeyiOS } from './PasskeyiOS';
import * as utils from './utils';

export class Passkey {
  static generateCreateRequest(
    userId: string,
    userName: string,
    challenge: string,
    options: Partial<CreateOptions>
  ): PasskeyRegistrationRequest {
    return {
      challenge,
      rp: {
        id: 'getclave.io',
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
        userVerification: options.userVerification ?? 'preferred',
        authenticatorAttachment: 'platform',
        residentKey: options.discoverable ?? 'preferred',
        requireResidentKey: options.discoverable === 'required',
      },
      attestation: options.attestation ? 'direct' : 'none',
    };
  }

  static generateSignRequest(
    credentialIds: Array<string>,
    challenge: string,
    options: Partial<SignOptions>
  ): PasskeyAuthenticationRequest {
    return {
      challenge,
      rpId: 'getclave.io',
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
  }

  /**
   * Creates a new Passkey
   *
   * @param userId The user's unique identifier
   * @param userName The user's name
   * @param challenge The FIDO2 Challenge without formatting
   * @param options An object containing options for the registration process
   * @returns The FIDO2 Attestation Result in JSON format
   * @throws
   */
  public static async create(
    userId: string,
    userName: string,
    challenge: string,
    options: Partial<CreateOptions> = {}
  ): Promise<PasskeyRegistrationResult> {
    if (!Passkey.isSupported) {
      throw NotSupportedError;
    }

    const challengeBase64 = utils.hextoBase64(challenge);

    const request = this.generateCreateRequest(
      userId,
      userName,
      challengeBase64,
      options
    );

    if (Platform.OS === 'android') {
      return PasskeyAndroid.register(request);
    }
    return PasskeyiOS.register(request, options.withSecurityKey ?? false);
  }

  /**
   * Authenticates using an existing Passkey and returns signature only
   *
   * @param credentialIds The credential IDs of the Passkey to authenticate with
   * @param challenge The FIDO2 Challenge without formatting
   * @options An object containing options for the authentication process
   * @returns The FIDO2 Assertion Result in JSON format
   * @throws
   */
  public static async sign(
    credentialIds: Array<string>,
    challenge: string,
    options: Partial<SignOptions> = {}
  ): Promise<string> {
    if (!Passkey.isSupported) {
      throw NotSupportedError;
    }

    const challengeBase64 = utils.hextoBase64(challenge);

    const request = this.generateSignRequest(
      credentialIds,
      challengeBase64,
      options
    );

    let authResponse: PasskeyAuthenticationResult;

    if (Platform.OS === 'android') {
      authResponse = await PasskeyAndroid.authenticate(request);
    } else {
      authResponse = await PasskeyiOS.authenticate(
        request,
        options.withSecurityKey ?? false
      );
    }

    const base64Decoded = utils.base64ToHex(authResponse.response.signature);
    const { r, s } = utils.derToRs(base64Decoded);
    return ['0x', r, s].join('');
  }

  /**
   * Authenticates using an existing Passkey and returns full response
   *
   * @param credentialIds The credential IDs of the Passkey to authenticate with
   * @param challenge The FIDO2 Challenge without formatting
   * @options An object containing options for the authentication process
   * @returns The FIDO2 Assertion Result in JSON format
   * @throws
   */
  public static async authenticate(
    credentialIds: Array<string>,
    challenge: string,
    options: Partial<SignOptions> = {}
  ): Promise<PasskeyAuthenticationResult> {
    if (!Passkey.isSupported) {
      throw NotSupportedError;
    }

    const challengeBase64 = utils.hextoBase64(challenge);

    const request = this.generateSignRequest(
      credentialIds,
      challengeBase64,
      options
    );

    if (Platform.OS === 'android') {
      return PasskeyAndroid.authenticate(request);
    } else {
      return PasskeyiOS.authenticate(request, options.withSecurityKey ?? false);
    }
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
    clientDataJSON: string; // Base64 and DER encoded
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
