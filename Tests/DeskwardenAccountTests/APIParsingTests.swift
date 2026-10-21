import Foundation
import Testing
@testable import DeskwardenAccount

struct APIParsingTests {
    @Test(arguments: [
        ("2026-10-21T09:03:26.1234567Z", 1792573406.1234567),
        ("2026-10-21T09:03:26.123Z", 1792573406.123),
        ("2026-10-21T09:03:26Z", 1792573406.0),
        ("2026-10-21T09:03:26.5", 1792573406.5),
    ])
    func parsesDotNetDates(string: String, expected: Double) throws {
        let date = try #require(BitwardenJSON.parseDate(string))
        #expect(abs(date.timeIntervalSince1970 - expected) < 0.001)
    }

    @Test func decodesPascalCaseTokenResponse() throws {
        let json = """
        {
          "access_token": "a.b.c", "expires_in": 3600, "token_type": "Bearer", "refresh_token": "refresh",
          "Key": "2.key", "PrivateKey": "2.private", "Kdf": 0, "KdfIterations": 600000,
          "TwoFactorToken": "remember-me",
          "UserDecryptionOptions": {
            "HasMasterPassword": true,
            "MasterPasswordUnlock": {
              "Kdf": { "KdfType": 1, "Iterations": 3, "Memory": 64, "Parallelism": 4 },
              "MasterKeyEncryptedUserKey": "2.wrapped", "Salt": "user@example.com"
            }
          }
        }
        """
        let token = try BitwardenJSON.decoder().decode(TokenResponse.self, from: Data(json.utf8))
        #expect(token.refresh_token == "refresh")
        #expect(token.twoFactorToken == "remember-me")
        let unlock = try #require(token.userDecryptionOptions?.masterPasswordUnlock)
        #expect(unlock.masterKeyEncryptedUserKey == "2.wrapped")
        #expect(unlock.kdfSettings == KdfSettings(kind: .argon2id, iterations: 3, memory: 64, parallelism: 4))
    }

    @Test func detectsTwoFactorRequired() throws {
        let json = """
        {
          "error": "invalid_grant", "error_description": "Two factor required.",
          "TwoFactorProviders": ["0", "1"],
          "TwoFactorProviders2": { "0": null, "1": { "Email": "u***@example.com" } }
        }
        """
        let error = try BitwardenJSON.decoder().decode(TokenErrorResponse.self, from: Data(json.utf8))
        #expect(BitwardenAPI.tokenError(error, status: 400) == .twoFactorRequired([.authenticator, .email], emailHint: "u***@example.com"))
    }

    @Test func detectsNewDeviceVerification() throws {
        let json = #"{ "error": "device_error", "error_description": "New device verification required." }"#
        let error = try BitwardenJSON.decoder().decode(TokenErrorResponse.self, from: Data(json.utf8))
        #expect(BitwardenAPI.tokenError(error, status: 400) == .newDeviceVerificationRequired)
    }

    @Test func reportsRejectedLoginWithServerMessage() throws {
        let json = """
        {
          "error": "invalid_grant", "error_description": "invalid_username_or_password",
          "ErrorModel": { "Message": "Username or password is incorrect. Try again.", "Object": "error" }
        }
        """
        let error = try BitwardenJSON.decoder().decode(TokenErrorResponse.self, from: Data(json.utf8))
        #expect(BitwardenAPI.tokenError(error, status: 400) == .loginRejected("Username or password is incorrect. Try again."))
    }

    @Test func readsJWTClaims() {
        // {"sub":"user-id","email":"u@example.com"}
        let token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLWlkIiwiZW1haWwiOiJ1QGV4YW1wbGUuY29tIn0.sig"
        #expect(JWT.claim("sub", in: token) == "user-id")
        #expect(JWT.claim("email", in: token) == "u@example.com")
        #expect(JWT.claim("sub", in: "not-a-jwt") == nil)
    }

    @Test func legacySaltIsTrimmedAndLowercased() {
        #expect(BitwardenAPI.legacySalt(for: "  User@Example.COM ") == "user@example.com")
    }
}
