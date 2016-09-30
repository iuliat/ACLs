
import win32security


def set_permissions(self, path, username, permissions,
                    inheritance=constants.ACE_INHERITED):
    user_sid, _, _ = win32security.LookupAccountName("", username)
    security_description = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
    dacl = security_description.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inheritance,
                               permissions, user_sid)
    security_description.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(path,
                                  win32security.DACL_SECURITY_INFORMATION,
                                  security_description)
