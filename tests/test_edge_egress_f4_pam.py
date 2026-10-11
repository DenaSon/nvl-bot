"""F4 PAM rule render and audit stays offline."""
import unittest

from edge_egress_f4_pam import (
    REQUIRED_ACCOUNT_LINE, inspect_deployment_root,
    verify_installed_gate_digest,
    inspect_pam_sshd, render_pam_change_review,
)


class F4PAMAuditTests(unittest.TestCase):
    def test_exact_first_account_rule_is_a_config_candidate_not_live_e2e(self):
        s=("# sshd PAM\nauth required pam_unix.so\n"
           +REQUIRED_ACCOUNT_LINE+"\n"
           +"@include common-account\n")
        verdict=inspect_pam_sshd(s,"usepam yes\n",protected_username="nvl0557")
        self.assertTrue(verdict.valid)
        self.assertTrue(verdict.installed)
        self.assertFalse(verdict.customer_ready)
        self.assertIn(REQUIRED_ACCOUNT_LINE,render_pam_change_review())

    def test_missing_bypassed_or_duplicate_pam_denied(self):
        for s in (
            "@include common-account\n",
            "account sufficient pam_permit.so\n"+REQUIRED_ACCOUNT_LINE,
            REQUIRED_ACCOUNT_LINE+"\n"+REQUIRED_ACCOUNT_LINE,
            REQUIRED_ACCOUNT_LINE+"\n"
            "account optional pam_exec.so /tmp/allow",
        ):
            with self.subTest(s=s):
                self.assertFalse(inspect_pam_sshd(s,"usepam yes").valid)

    def test_prior_pam_account_include_is_not_mistaken_for_safe_order(self):
        pam="@include common-account\n"+REQUIRED_ACCOUNT_LINE+"\n"
        result=inspect_pam_sshd(pam,"usepam yes\n")
        self.assertFalse(result.valid)
        self.assertIn("PAM_INCLUDED_ACCOUNT_BEFORE_GUARD",result.issues)

    def test_usepam_disabled_or_unproven(self):
        for s in ("usepam no","", "usepam yes\nusepam no"):
            with self.subTest(s=s):
                verdict=inspect_pam_sshd(REQUIRED_ACCOUNT_LINE,s)
                self.assertFalse(verdict.valid)

    def test_missing_unreviewed_or_untrusted_pam_module_fails_closed(self):
        for digest in ("", "foo", "A"*64, "0"*64):
            with self.subTest(digest=digest):
                self.assertFalse(verify_installed_gate_digest(digest))
        self.assertFalse(verify_installed_gate_digest(
            "a"*64,module_path="/tmp/unreviewed.py",
        ))

    def test_module_path_and_ownership_are_checked(self):
        self.assertTrue(inspect_deployment_root(
            "/opt/nvl-egress/edge_egress_uid_admission.py",
            root_owner_uid=0,mode=0o644,is_symlink=False,
        ))
        for path,uid,mode,link in (
            ("/tmp/edge_egress_uid_admission.py",0,0o644,False),
            ("/opt/nvl-egress/../bad.py",0,0o644,False),
            ("/opt/nvl-egress/safe.py",1000,0o644,False),
            ("/opt/nvl-egress/safe.py",0,0o666,False),
            ("/opt/nvl-egress/safe.py",0,0o644,True),
        ):
            self.assertFalse(inspect_deployment_root(
                path,root_owner_uid=uid,mode=mode,is_symlink=link,
            ))


if __name__=="__main__":
    unittest.main()
