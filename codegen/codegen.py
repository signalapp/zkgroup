import codegen_java
import codegen_ffiapi
import codegen_ffiapijava
import codegen_simpleapi
import codegen_swift

class Name:
    def __init__(self, name):
        self.name = name

    def snake(self):
        return self.name

    def camel(self):
        pieces = self.name.split("_")
        ret = ""
        for piece in pieces:
            ret += piece[0].upper() + piece[1:]
        return ret

    def lower_camel(self):
        pieces = self.name.split("_")
        ret = ""
        first = True
        for piece in pieces:
            if first:
                ret += piece[0] + piece[1:]
            else:
                ret += piece[0].upper() + piece[1:]
            first = False
        return ret

class StaticMethodDescriptor:
    def __init__(self, method_name, return_type, return_name, params, rustCode, verification=False, runtime_error=False,
            return_size_increment=0, relative_return_size=None):
        self.method_name = Name(method_name)
        self.return_type = return_type
        self.return_name = Name(return_name)
        self.params = params # list of (type, name) pairs
        self.rustCode = rustCode
        self.verification = verification
        self.runtime_error = runtime_error
        self.return_size_increment = return_size_increment
        self.relative_return_size = relative_return_size

class MethodDescriptor:
    def __init__(self, method_name, return_type, return_name, params, rustCode, verification=False, runtime_error=False,
            unused_self=False, return_size_increment=0, relative_return_size=None):
        self.method_name = Name(method_name)
        self.return_type = return_type
        self.return_name = Name(return_name)
        self.params = params # list of (type, name) pairs
        self.rustCode = rustCode
        self.verification = verification
        self.runtime_error = runtime_error
        self.unused_self = unused_self
        self.return_size_increment = return_size_increment
        self.relative_return_size = relative_return_size

class ClassDescriptor:
    def __init__(self, class_name, dir_name, rust_class_name, class_len_int, check_valid_contents=True, no_class=False, no_serialize=False,
            runtime_error_on_serialize=False, string_contents=False, wrap_class=None):
        self.class_name = Name(class_name)
        self.class_len = class_name.upper() + "_LEN" # length in bytes
        self.static_methods = [] # list of StaticMethodDescriptor
        self.methods = [] # list of MethodDescriptor,
        self.dir_name = Name(dir_name)
        self.rust_class_name = rust_class_name
        self.class_len_int = class_len_int
        if check_valid_contents and wrap_class == None:
            self.add_method("check_valid_contents", "boolean", "None", [], "", unused_self=True);
            self.check_valid_contents = True
        else:
            self.check_valid_contents = False
        self.no_class = no_class
        self.no_serialize = no_serialize
        self.runtime_error_on_serialize = runtime_error_on_serialize
        self.string_contents = string_contents
        if wrap_class != None:
            self.wrap_class = Name(wrap_class)
        else:
            self.wrap_class = None

    def add_static_method(
            self, method_name, return_type, return_name, params, rust_code="", verification=False, runtime_error=False,
            return_size_increment=0, relative_return_size=None):
        params2 = [(p[0], Name(p[1])) for p in params]
        self.static_methods.append(StaticMethodDescriptor(
            method_name, return_type, return_name, params2, rust_code, verification, runtime_error,
            return_size_increment, relative_return_size=relative_return_size))

    def add_method(
            self, method_name, return_type, return_name, params, rust_code="", verification=False, runtime_error=False,
            return_size_increment=0, unused_self=False, relative_return_size=None):
        params2 = [(p[0], Name(p[1])) for p in params]
        self.methods.append(MethodDescriptor(
            method_name, return_type, return_name, params2, rust_code, verification, runtime_error, unused_self,
            return_size_increment, relative_return_size=relative_return_size))

def define_classes():
    classes = []

    c = ClassDescriptor("group_identifier", "groups", "simple_types::GroupIdentifierBytes", 32, check_valid_contents=False)
    classes.append(c)

    c = ClassDescriptor("profile_key_version", "profiles", "api::profiles::ProfileKeyVersion", 64, check_valid_contents=False, string_contents=True)
    classes.append(c)

    c = ClassDescriptor("notary_signature", "", "simple_types::NotarySignatureBytes", 64, check_valid_contents=False)
    classes.append(c)

    c = ClassDescriptor("receipt_serial", "receipts", "simple_types::ReceiptSerialBytes", 16, check_valid_contents=False)
    classes.append(c)

    c = ClassDescriptor("profile_key", "profiles", "api::profiles::ProfileKey", 32, check_valid_contents=False)
    c.add_method("get_commitment", "class", "profile_key_commitment", [("UUID", "uuid")],
            """    let profile_key_commitment = profile_key.get_commitment(uuid);""");
    c.add_method("get_profile_key_version", "class", "profile_key_version", [("UUID", "uuid")],
            """    let profile_key_version = profile_key.get_profile_key_version(uuid);""")
    classes.append(c)

    c = ClassDescriptor("profile_key_commitment", "profiles", "api::profiles::ProfileKeyCommitment", 97)

    classes.append(c)

    c = ClassDescriptor("group_master_key", "groups", "api::groups::GroupMasterKey", 32, check_valid_contents=False)
    classes.append(c)

    c = ClassDescriptor("group_secret_params", "groups", "api::groups::GroupSecretParams", 289, runtime_error_on_serialize=True)

    c.add_static_method("generate_deterministic", "class", "group_secret_params", [("class", "randomness")],
            """    let group_secret_params = api::groups::GroupSecretParams::generate(randomness);""" )

    c.add_static_method("derive_from_master_key", "class", "group_secret_params", [("class", "group_master_key")],
            """    let group_secret_params = api::groups::GroupSecretParams::derive_from_master_key(group_master_key);""", runtime_error=True)

    c.add_method("get_master_key", "class", "group_master_key", [],
            """    let group_master_key = group_secret_params.get_master_key();""")

    c.add_method("get_public_params", "class", "group_public_params", [],
            """    let group_public_params = group_secret_params.get_public_params();""")

    classes.append(c)

    c = ClassDescriptor("client_zk_group_cipher", "groups", "api::groups::ClientZkGroupCipher", 192, wrap_class="group_secret_params")

    c.add_method("encrypt_uuid", "class", "uuid_ciphertext", [("UUID", "uuid")],
            """    let uuid_ciphertext = group_secret_params.encrypt_uuid(uuid);""", runtime_error=True)

    c.add_method("decrypt_uuid", "UUID", "uuid", [("class", "uuid_ciphertext")],
            """    let uuid = match group_secret_params.decrypt_uuid(uuid_ciphertext) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""")

    c.add_method("encrypt_profile_key", "class", "profile_key_ciphertext", [("class", "profile_key"), ("UUID", "uuid")],
            """    let profile_key_ciphertext = group_secret_params.encrypt_profile_key(profile_key, uuid);""", runtime_error=True)

    c.add_method("decrypt_profile_key", "class", "profile_key", [("class", "profile_key_ciphertext"), ("UUID", "uuid")],
            """    let profile_key = match group_secret_params.decrypt_profile_key(profile_key_ciphertext, uuid) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""")

    c.add_method("encrypt_blob_deterministic", "byte[]", "blob_ciphertext", [("class", "randomness"), ("byte[]", "plaintext")],
             """    let blob_ciphertext = match group_secret_params.encrypt_blob(randomness, plaintext) {
         Ok(result) => result,
         Err(_) => return FFI_RETURN_INPUT_ERROR,
     };""", return_size_increment=+29, relative_return_size=1)

    c.add_method("decrypt_blob", "byte[]", "plaintext", [("byte[]", "blob_ciphertext")],
            """    let plaintext = match group_secret_params.decrypt_blob(blob_ciphertext) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""", return_size_increment=-29, relative_return_size=0)

    classes.append(c)

    c = ClassDescriptor("server_secret_params", "", "api::ServerSecretParams", 1537, runtime_error_on_serialize=True)
    c.add_static_method("generate_deterministic", "class", "server_secret_params", [("class", "randomness")],
            """    let server_secret_params = api::ServerSecretParams::generate(randomness);""")

    c.add_method("get_public_params", "class", "server_public_params", [],
        """    let server_public_params = server_secret_params.get_public_params();""")

    c.add_method("sign_deterministic", "class", "notary_signature", [("class", "randomness"), ("byte[]", "message") ],
        """    let notary_signature = match server_secret_params.sign(randomness, message) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""", runtime_error=True)

    classes.append(c)

    c = ClassDescriptor("client_zk_auth_operations", "auth", "api::auth::ClientZkAuthOperations", 256, wrap_class="server_public_params")

    c.add_method("receive_auth_credential", "class", "auth_credential", [("UUID", "uuid"), ("int", "redemption_time"), ("class", "auth_credential_response")],
     """    let auth_credential = match server_public_params.receive_auth_credential(uuid, redemption_time, &auth_credential_response) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""")

    c.add_method("create_auth_credential_presentation_deterministic", "class", "auth_credential_presentation", [("class", "randomness"), ("class", "group_secret_params"), ("class", "auth_credential")],
    """    let auth_credential_presentation = server_public_params.create_auth_credential_presentation(randomness, group_secret_params, auth_credential);""", runtime_error=True)

    classes.append(c)

    c = ClassDescriptor("client_zk_profile_operations", "profiles", "api::profiles::ClientZkProfileOperations", 256, wrap_class="server_public_params")

    c.add_method("create_profile_key_credential_request_context_deterministic", "class", "profile_key_credential_request_context", [("class", "randomness"), ("UUID", "uuid"), ("class", "profile_key")],
    """    let profile_key_credential_request_context = server_public_params.create_profile_key_credential_request_context(randomness, uuid, profile_key);""", runtime_error=True)

    c.add_method("create_pni_credential_request_context_deterministic", "class", "pni_credential_request_context", [("class", "randomness"), ("UUID", "aci"), ("UUID", "pni"), ("class", "profile_key")],
    """    let pni_credential_request_context = server_public_params.create_pni_credential_request_context(randomness, aci, pni, profile_key);""", runtime_error=True)

    c.add_method("receive_profile_key_credential", "class", "profile_key_credential", [("class", "profile_key_credential_request_context"), ("class", "profile_key_credential_response")],
     """    let profile_key_credential = match server_public_params.receive_profile_key_credential(&profile_key_credential_request_context, &profile_key_credential_response) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""")

    c.add_method("receive_pni_credential", "class", "pni_credential", [("class", "pni_credential_request_context"), ("class", "pni_credential_response")],
     """    let pni_credential = match server_public_params.receive_pni_credential(&pni_credential_request_context, &pni_credential_response) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""")

    c.add_method("create_profile_key_credential_presentation_deterministic", "class", "profile_key_credential_presentation", [("class", "randomness"), ("class", "group_secret_params"), ("class", "profile_key_credential") ],
    """    let profile_key_credential_presentation = server_public_params.create_profile_key_credential_presentation(randomness, group_secret_params, profile_key_credential);""", runtime_error=True)

    c.add_method("create_pni_credential_presentation_deterministic", "class", "pni_credential_presentation", [("class", "randomness"), ("class", "group_secret_params"), ("class", "pni_credential") ],
    """    let pni_credential_presentation = server_public_params.create_pni_credential_presentation(randomness, group_secret_params, pni_credential);""", runtime_error=True)

    classes.append(c)

    c = ClassDescriptor("client_zk_receipt_operations", "receipts", "api::receipts::ClientZkReceiptOperations", 256, wrap_class="server_public_params")

    c.add_method("create_receipt_credential_request_context_deterministic", "class", "receipt_credential_request_context", [("class", "randomness"), ("class", "receipt_serial")],
                 """    let receipt_credential_request_context = server_public_params.create_receipt_credential_request_context(randomness, receipt_serial);""")

    c.add_method("receive_receipt_credential", "class", "receipt_credential", [("class", "receipt_credential_request_context"), ("class", "receipt_credential_response")],
                 """    let receipt_credential = match server_public_params.receive_receipt_credential(&receipt_credential_request_context, &receipt_credential_response) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""")

    c.add_method("create_receipt_credential_presentation_deterministic", "class", "receipt_credential_presentation", [("class", "randomness"), ("class", "receipt_credential")],
                 """    let receipt_credential_presentation = server_public_params.create_receipt_credential_presentation(randomness, &receipt_credential);""")

    classes.append(c)

    c = ClassDescriptor("server_zk_auth_operations", "auth", "api::auth::ServerZkAuthOperations", 544, wrap_class="server_secret_params")

    c.add_method("issue_auth_credential_deterministic", "class", "auth_credential_response", [("class", "randomness"), ("UUID", "uuid"), ("int", "redemption_time")],
            """    let auth_credential_response = server_secret_params.issue_auth_credential(randomness, uuid, redemption_time);""", runtime_error=True)

    c.add_method("verify_auth_credential_presentation", "boolean", "None", [("class", "group_public_params"), ("class", "auth_credential_presentation")  ],
    """    match server_secret_params.verify_auth_credential_presentation(group_public_params, &auth_credential_presentation) {
        Ok(_) => (),
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    }""")

    classes.append(c)

    c = ClassDescriptor("server_zk_profile_operations", "profiles", "api::profiles::ServerZkProfileOperations", 544, wrap_class="server_secret_params")

    c.add_method("issue_profile_key_credential_deterministic", "class", "profile_key_credential_response", [("class", "randomness"), ("class", "profile_key_credential_request"), ("UUID", "uuid"), ("class", "profile_key_commitment")],
            """    let profile_key_credential_response = match server_secret_params.issue_profile_key_credential(
        randomness,
        &profile_key_credential_request,
        uuid,
        profile_key_commitment,
    ) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""")

    c.add_method("issue_pni_credential_deterministic", "class", "pni_credential_response", [("class", "randomness"), ("class", "profile_key_credential_request"), ("UUID", "aci"), ("UUID", "pni"), ("class", "profile_key_commitment")],
            """    let pni_credential_response = match server_secret_params.issue_pni_credential(
        randomness,
        &profile_key_credential_request,
        aci,
        pni,
        profile_key_commitment,
    ) {
        Ok(result) => result,
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    };""")

    c.add_method("verify_profile_key_credential_presentation", "boolean", "None", [("class", "group_public_params"), ("class", "profile_key_credential_presentation") ],
    """    match server_secret_params.verify_profile_key_credential_presentation(group_public_params, &profile_key_credential_presentation) {
        Ok(_) => (),
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    }""")

    c.add_method("verify_pni_credential_presentation", "boolean", "None", [("class", "group_public_params"), ("class", "pni_credential_presentation") ],
    """    match server_secret_params.verify_pni_credential_presentation(group_public_params, &pni_credential_presentation) {
        Ok(_) => (),
        Err(_) => return FFI_RETURN_INPUT_ERROR,
    }""")

    classes.append(c)

    c = ClassDescriptor("server_zk_receipt_operations", "receipts", "api::receipts::ServerZkReceiptOperations", 544, wrap_class="server_secret_params")

    c.add_method("issue_receipt_credential_deterministic", "class", "receipt_credential_response", [("class", "randomness"), ("class", "receipt_credential_request"), ("long", "receipt_expiration_time"), ("long", "receipt_level")],
                 """    let receipt_credential_response = server_secret_params.issue_receipt_credential(
        randomness,
        &receipt_credential_request,
        receipt_expiration_time,
        receipt_level,
    );""")

    c.add_method("verify_receipt_credential_presentation", "boolean", "None", [("class", "receipt_credential_presentation")],
                 """    match server_secret_params.verify_receipt_credential_presentation(&receipt_credential_presentation) {
        Ok(_) => (),
        Err(_) => return FFI_RETURN_INPUT_ERROR,
        }""")

    classes.append(c)

    c = ClassDescriptor("group_public_params", "groups", "api::groups::GroupPublicParams", 97)
    c.add_method("get_group_identifier", "class", "group_identifier", [],
            """    let group_identifier = group_public_params.get_group_identifier();""")

    classes.append(c)

    c = ClassDescriptor("server_public_params", "", "api::ServerPublicParams", 289, runtime_error_on_serialize=True)

    c.add_method("verify_signature", "boolean", "None", [("byte[]", "message"), ("class", "notary_signature")],
            """    match server_public_params.verify_signature(message, notary_signature) {
        Ok(_) => (),
        _ => return FFI_RETURN_INPUT_ERROR,
    };""")

    classes.append(c)

    c = ClassDescriptor("auth_credential_response", "auth", "api::auth::AuthCredentialResponse", 361)
    classes.append(c)

    c = ClassDescriptor("auth_credential", "auth", "api::auth::AuthCredential", 181)
    classes.append(c)

    c = ClassDescriptor("auth_credential_presentation", "auth", "api::auth::AuthCredentialPresentation", 493)
    c.add_method("get_uuid_ciphertext", "class", "uuid_ciphertext", [],
            """    let uuid_ciphertext = auth_credential_presentation.get_uuid_ciphertext();""");
    c.add_method("get_redemption_time", "int", "redemption_time", [],
            """    let redemption_time = auth_credential_presentation.get_redemption_time();""");
    classes.append(c)

    c = ClassDescriptor("profile_key_credential_request_context", "profiles", "api::profiles::ProfileKeyCredentialRequestContext", 473)
    c.add_method("get_request", "class", "profile_key_credential_request", [],
            """    let profile_key_credential_request = profile_key_credential_request_context.get_request();""" )
    classes.append(c)

    c = ClassDescriptor("pni_credential_request_context", "profiles", "api::profiles::PniCredentialRequestContext", 489)
    c.add_method("get_request", "class", "profile_key_credential_request", [],
            """    let profile_key_credential_request = pni_credential_request_context.get_request();""" )
    classes.append(c)

    c = ClassDescriptor("profile_key_credential_request", "profiles", "api::profiles::ProfileKeyCredentialRequest", 329)
    classes.append(c)

    c = ClassDescriptor("profile_key_credential_response", "profiles", "api::profiles::ProfileKeyCredentialResponse", 457)
    classes.append(c)

    c = ClassDescriptor("pni_credential_response", "profiles", "api::profiles::PniCredentialResponse", 521)
    classes.append(c)

    c = ClassDescriptor("profile_key_credential", "profiles", "api::profiles::ProfileKeyCredential", 145)
    classes.append(c)

    c = ClassDescriptor("pni_credential", "profiles", "api::profiles::PniCredential", 161)
    classes.append(c)

    c = ClassDescriptor("profile_key_credential_presentation", "profiles", "api::profiles::ProfileKeyCredentialPresentation", 713)
    c.add_method("get_uuid_ciphertext", "class", "uuid_ciphertext", [],
            """    let uuid_ciphertext = profile_key_credential_presentation.get_uuid_ciphertext();""");
    c.add_method("get_profile_key_ciphertext", "class", "profile_key_ciphertext", [],
            """    let profile_key_ciphertext = profile_key_credential_presentation.get_profile_key_ciphertext();""");
    classes.append(c)

    c = ClassDescriptor("pni_credential_presentation", "profiles", "api::profiles::PniCredentialPresentation", 841)
    c.add_method("get_aci_ciphertext", "class", "uuid_ciphertext", [],
            """    let uuid_ciphertext = pni_credential_presentation.get_aci_ciphertext();""");
    c.add_method("get_pni_ciphertext", "class", "uuid_ciphertext", [],
            """    let uuid_ciphertext = pni_credential_presentation.get_pni_ciphertext();""");
    c.add_method("get_profile_key_ciphertext", "class", "profile_key_ciphertext", [],
            """    let profile_key_ciphertext = pni_credential_presentation.get_profile_key_ciphertext();""");
    classes.append(c)

    c = ClassDescriptor("receipt_credential_request_context", "receipts", "api::receipts::ReceiptCredentialRequestContext", 177)
    c.add_method("get_request", "class", "receipt_credential_request", [],
                 """    let receipt_credential_request = receipt_credential_request_context.get_request();""")
    classes.append(c)

    c = ClassDescriptor("receipt_credential_request", "receipts", "api::receipts::ReceiptCredentialRequest", 97)
    classes.append(c)

    c = ClassDescriptor("receipt_credential_response", "receipts", "api::receipts::ReceiptCredentialResponse", 409)
    classes.append(c)

    c = ClassDescriptor("receipt_credential", "receipts", "api::receipts::ReceiptCredential", 129)
    c.add_method("get_receipt_expiration_time", "long", "receipt_expiration_time", [],
                 """    let receipt_expiration_time = receipt_credential.get_receipt_expiration_time();""")
    c.add_method("get_receipt_level", "long", "receipt_level", [],
                 """    let receipt_level = receipt_credential.get_receipt_level();""")
    classes.append(c)

    c = ClassDescriptor("receipt_credential_presentation", "receipts", "api::receipts::ReceiptCredentialPresentation", 329)
    c.add_method("get_receipt_expiration_time", "long", "receipt_expiration_time", [],
                 """    let receipt_expiration_time = receipt_credential_presentation.get_receipt_expiration_time();""")
    c.add_method("get_receipt_level", "long", "receipt_level", [],
                 """    let receipt_level = receipt_credential_presentation.get_receipt_level();""")
    c.add_method("get_receipt_serial", "class", "receipt_serial", [],
                 """    let receipt_serial = receipt_credential_presentation.get_receipt_serial_bytes();""")
    classes.append(c)

    c = ClassDescriptor("uuid_ciphertext", "groups", "api::groups::UuidCiphertext", 65)
    classes.append(c)

    c = ClassDescriptor("profile_key_ciphertext", "groups", "api::groups::ProfileKeyCiphertext", 65)
    classes.append(c)

    c = ClassDescriptor("randomness", "", "simple_types::RandomnessBytes", 32, no_class=True)
    classes.append(c)

    c = ClassDescriptor("uuid", "", "simple_types::UidBytes", 32, no_class=True)
    classes.append(c)

    return classes



classes = define_classes()
codegen_java.produce_output(classes)
codegen_ffiapi.produce_output(classes)
codegen_ffiapijava.produce_output(classes)
codegen_simpleapi.produce_output(classes)
codegen_swift.produce_output(classes)
