@preconcurrency import BitwardenSdk
import Foundation

// Sync models → SDK records, following the official iOS app's mapping
// (BitwardenSdk+Vault.swift). Card, identity, attachment, passkey and history
// data isn't decoded: the secrets socket and SSH agent never serve it.

extension BitwardenSdk.Cipher {
    /// `nil` for item types this SDK build doesn't know.
    init?(_ model: SyncResponse.Cipher) {
        guard let type = BitwardenSdk.CipherType(rawValue: model.type) else { return nil }
        self.init(
            id: model.id,
            organizationId: model.organizationId,
            folderId: model.folderId,
            collectionIds: model.collectionIds ?? [],
            key: model.key,
            name: model.name,
            notes: model.notes,
            type: type,
            login: model.login.map(BitwardenSdk.Login.init),
            identity: nil,
            card: nil,
            secureNote: model.secureNote.map(BitwardenSdk.SecureNote.init),
            sshKey: model.sshKey.map(BitwardenSdk.SshKey.init),
            bankAccount: nil,
            driversLicense: nil,
            passport: nil,
            favorite: model.favorite,
            reprompt: model.reprompt.flatMap(BitwardenSdk.CipherRepromptType.init(rawValue:)) ?? BitwardenSdk.CipherRepromptType.none,
            organizationUseTotp: model.organizationUseTotp,
            edit: model.edit,
            permissions: nil,
            viewPassword: model.viewPassword,
            localData: nil,
            attachments: nil,
            fields: model.fields?.compactMap(BitwardenSdk.Field.init),
            passwordHistory: nil,
            creationDate: model.creationDate,
            deletedDate: model.deletedDate,
            revisionDate: model.revisionDate,
            archivedDate: model.archivedDate,
            data: model.data,
            partialData: nil
        )
    }
}

extension BitwardenSdk.Login {
    init(_ model: SyncResponse.Login) {
        self.init(
            username: model.username,
            password: model.password,
            passwordRevisionDate: model.passwordRevisionDate,
            uris: model.uris?.map(BitwardenSdk.LoginUri.init),
            totp: model.totp,
            autofillOnPageLoad: model.autofillOnPageLoad,
            fido2Credentials: nil
        )
    }
}

extension BitwardenSdk.LoginUri {
    init(_ model: SyncResponse.LoginURI) {
        self.init(
            uri: model.uri,
            match: model.match.flatMap(BitwardenSdk.UriMatchType.init(rawValue:)),
            uriChecksum: model.uriChecksum
        )
    }
}

extension BitwardenSdk.Field {
    init?(_ model: SyncResponse.Field) {
        guard let type = BitwardenSdk.FieldType(rawValue: model.type) else { return nil }
        self.init(name: model.name, value: model.value, type: type, linkedId: model.linkedId)
    }
}

extension BitwardenSdk.SecureNote {
    init(_ model: SyncResponse.SecureNote) {
        self.init(type: BitwardenSdk.SecureNoteType(rawValue: model.type) ?? .generic)
    }
}

extension BitwardenSdk.SshKey {
    init(_ model: SyncResponse.SSHKey) {
        self.init(privateKey: model.privateKey, publicKey: model.publicKey, fingerprint: model.keyFingerprint)
    }
}

extension BitwardenSdk.Folder {
    init(_ model: SyncResponse.Folder) {
        self.init(id: model.id, name: model.name, revisionDate: model.revisionDate)
    }
}
