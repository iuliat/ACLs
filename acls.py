import ctypes
secur32 = ctypes.windll.secur32
kernel32 = ctypes.windll.kernel32
advapi = ctypes.windll.AdvApi32


def get_last_error():
    error_code = kernel32.GetLastError()
    kernel32.SetLastError(0)
    return error_code

def get_sid(username):
    sid_buff_sz = ctypes.c_ulong(1024)
    sid_buff = (ctypes.c_wchar * sid_buff_sz.value)()
    domain_buff_sz = ctypes.c_ulong(128)
    domain_buff = (ctypes.c_wchar * domain_buff_sz.value)()
    # p_sid_string = ctypes.c_wchar_p()
    peUse = ctypes.c_uint()
    ret_val = advapi.LookupAccountNameW(
        None, ctypes.c_wchar_p(username),
        ctypes.byref(sid_buff), ctypes.byref(sid_buff_sz),
        ctypes.byref(domain_buff), ctypes.byref(domain_buff_sz),
        ctypes.byref(peUse))
    if not ret_val:
        err_code = get_last_error()
        raise Exception("Could not lookup username.")
    # ret_val = advapi.ConvertSidToStringSidW(
    #     ctypes.byref(sid_buff), ctypes.byref(p_sid_string))
    # if not ret_val:
    #     err_code = get_last_error()
    #     raise Exception("Could not convert sid to string.")
    # sid = p_sid_string.value
    # kernel32.LocalFree(p_sid_string)
    #return sid
    return sid_buff

# DACL_SECURITY_INFORMATION = 4
def get_file_security(path):
    DACL_SECURITY_INFORMATION = 4
    security_description_sz = ctypes.c_ulong(1024)
    security_description = (ctypes.c_char * security_description_sz.value)()
    ret_val = advapi.GetFileSecurityW(path, DACL_SECURITY_INFORMATION,
                                      ctypes.byref(security_description),
                                      1024,ctypes.byref(ctypes.c_ulong()))
    if not ret_val:
        err_code = get_last_error()
        raise Exception("get_file_security_exception. Error code:%s" % err_code)
    return security_description

def get_security_descriptor_dacl(security_description):
    is_valid = ctypes.c_bool()
    is_retrieved = ctypes.c_bool()
    dacl_sz = ctypes.c_ulong(1024)
    pDacl = (ctypes.c_wchar * dacl_sz.value)()
    ret_val=advapi.GetSecurityDescriptorDacl(security_description,
                                             ctypes.byref(is_valid),
                                             ctypes.byref(pDacl),
                                             ctypes.byref(is_retrieved))
    if not ret_val:
        err_code = get_last_error()
        raise Exception("get_file_security_exception. Error code:%s" % err_code)
    print 'Valid: %s' % is_valid
    print 'Retrieved: %s' % is_retrieved
    return pDacl

def add_access_allowed_ace_ex(pDACL, DACL_revision_level, ACE_inheritance_flag,
                              access_rights_mask, pSID):
    # DACL_revision_level can be: 
    #    ACL_REVISION (=2)
    #    ACL_REVISION_DS (=4)
    DACL_revision_level = 2
    # DACL_revision_level can be: 
    #    ACL_REVISION (=2)
    #    ACL_REVISION_DS (=4)
    # ACE_inheritance_flag can be:
    #    CONTAINER_INHERIT_ACE       (=2)
    #    INHERIT_ONLY_ACE            (=8)
    #    INHERITED_ACE               (=16)
    #    NO_PROPAGATE_INHERIT_ACE    (=4)
    #    OBJECT_INHERIT_ACE          (=1)
    ACE_inheritance_flag = 2
    access_rights_mask = 1180063
    ret=advapi.AddAccessAllowedAceEx(pDACL, DACL_revision_level,
                                     ACE_inheritance_flag, access_rights_mask,
                                     pSID)
    if not ret:
        err_code = get_last_error()
        # Fails with 1306: revision level mismatch error
        raise Exception("add_access_allowed_ace_ex exception."
                        "Error code:%s" % err_code)
    return pDACL

# The security descriptor passed to SetSecurityDescriptorDacl must be
# in the absolute format. RegGetKeySecurity and GetFileSecurity functions
# return security descriptors in the self-relative format. Use 
# MakeAbsoluteSD function to convert a self-relative security
# descriptor into the absolute format.
def set_security_description_dacl(security_description, pDacl):
    ret=advapi.SetSecurityDescriptorDacl(security_description, 1, pDacl, 0)
    if not ret:
        err_code = get_last_error()
        raise Exception("add_access_allowed_ace_ex exception."
                        "Error code:%s" % err_code)


