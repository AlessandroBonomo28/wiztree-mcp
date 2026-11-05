"""Windows launch regressions; no real processes or UAC prompts are created."""

import ctypes
import unittest
from unittest.mock import Mock, patch

import wiztree_mcp as w


class LaunchTests(unittest.TestCase):
    def test_drive_roots_use_cli_drive_spec_without_changing_cache_paths(self):
        with patch.object(w, "resolve_wiztree_exe", return_value="WizTree64.exe"), \
                patch.object(w, "is_elevated", return_value=False), \
                patch.object(w, "_run_elevated", return_value=0) as launch:
            for target in ["C:", "C:\\", "C:/", "E:\\"]:
                for args in [
                    w.build_export_args(target, "out.csv", w.ExportOptions(admin=True)),
                    w.build_treemap_args(target, "out.png", 400, 300, False, False, False, True),
                ]:
                    original = args.copy()
                    result = w.run_wiztree(args, 20)
                    self.assertEqual(launch.call_args.args[1][0], target[:2])
                    self.assertEqual(args, original)
                    self.assertEqual(result.exit_code, 0)
                    self.assertFalse(result.timed_out)
            self.assertEqual(w.norm_path("C:"), "C:\\")

    def test_non_drive_target_and_non_admin_launch_are_preserved(self):
        args = [r"C:\a folder\日本語", "/export=out.csv", "/admin=0"]
        with patch.object(w, "resolve_wiztree_exe", return_value="WizTree64.exe"), \
                patch.object(w.subprocess, "Popen") as popen, \
                patch.object(w, "_run_elevated") as elevated:
            popen.return_value.returncode = 0
            w.run_wiztree(args, 20)
            self.assertEqual(popen.call_args.args[0], ["WizTree64.exe", *args])
            popen.return_value.wait.assert_called_once_with(timeout=20)
            elevated.assert_not_called()

    def test_already_elevated_server_uses_existing_process_wait(self):
        with patch.object(w, "resolve_wiztree_exe", return_value="WizTree64.exe"), \
                patch.object(w, "is_elevated", return_value=True), \
                patch.object(w.subprocess, "Popen") as popen, \
                patch.object(w, "_run_elevated") as elevated:
            popen.return_value.returncode = 0
            w.run_wiztree(["C:\\", "/admin=1"], 20)
            popen.return_value.wait.assert_called_once_with(timeout=20)
            elevated.assert_not_called()


class ElevatedProcessTests(unittest.TestCase):
    def setUp(self):
        self.shell = Mock()
        self.kernel = Mock()
        self.dll = patch.object(w.ctypes, "WinDLL", side_effect=[self.shell, self.kernel])
        self.dll.start()
        self.addCleanup(self.dll.stop)
        self.handle = 0x1234567887654321 if ctypes.sizeof(ctypes.c_void_p) == 8 else 1234

        def launch(pointer):
            info = pointer._obj
            self.assertEqual(info.lpVerb, "runas")
            self.assertEqual(info.nShow, 0)
            self.assertTrue(info.fMask & 0x40)
            self.assertEqual(info.lpFile, r"C:\Program Files\WizTree\WizTree64.exe")
            self.parameters = info.lpParameters
            info.hProcess = self.handle
            return True

        def exit_code(handle, pointer):
            pointer._obj.value = self.code
            return True

        self.shell.ShellExecuteExW.side_effect = launch
        self.kernel.WaitForSingleObject.return_value = 0
        self.kernel.GetExitCodeProcess.side_effect = exit_code
        self.kernel.TerminateProcess.return_value = True
        self.code = 0

    def run_scan(self):
        return w._run_elevated(
            r"C:\Program Files\WizTree\WizTree64.exe",
            ["C:", "/export=C:\\a folder\\日本語.csv", "/admin=1"],
            20,
        )

    def test_waits_for_elevated_handle_before_reading_exit_code(self):
        def wait(handle, milliseconds):
            self.kernel.GetExitCodeProcess.assert_not_called()
            self.assertEqual((handle, milliseconds), (self.handle, 20000))
            return 0

        self.kernel.WaitForSingleObject.side_effect = wait
        self.assertEqual(self.run_scan(), 0)
        self.assertIn('"/export=C:\\a folder\\日本語.csv"', self.parameters)
        self.kernel.CloseHandle.assert_called_once_with(self.handle)

    def test_cancelled_consent_is_an_error_without_a_process_wait(self):
        self.shell.ShellExecuteExW.side_effect = lambda _: False
        with patch.object(w.ctypes, "get_last_error", return_value=1223):
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                self.run_scan()
        self.kernel.WaitForSingleObject.assert_not_called()
        self.kernel.CloseHandle.assert_not_called()

    def test_timeout_stops_only_launched_process_and_rejects_partial_output(self):
        self.kernel.WaitForSingleObject.side_effect = [0x102, 0]
        with self.assertRaises(TimeoutError):
            self.run_scan()
        self.kernel.TerminateProcess.assert_called_once_with(self.handle, 1)
        self.kernel.GetExitCodeProcess.assert_not_called()
        self.kernel.CloseHandle.assert_called_once_with(self.handle)

    def test_failed_termination_is_reported_and_handle_closed(self):
        self.kernel.WaitForSingleObject.return_value = 0x102
        self.kernel.TerminateProcess.return_value = False
        with self.assertRaisesRegex(RuntimeError, "could not be stopped"):
            self.run_scan()
        self.kernel.CloseHandle.assert_called_once_with(self.handle)

    def test_failed_process_exit_does_not_accept_output(self):
        self.code = 2
        with self.assertRaisesRegex(RuntimeError, "exit code 2"):
            self.run_scan()
        self.kernel.CloseHandle.assert_called_once_with(self.handle)

    def test_wait_failure_closes_handle(self):
        self.kernel.WaitForSingleObject.return_value = 0xFFFFFFFF
        with patch.object(w.ctypes, "get_last_error", return_value=6):
            with self.assertRaises(OSError):
                self.run_scan()
        self.kernel.CloseHandle.assert_called_once_with(self.handle)


if __name__ == "__main__":
    unittest.main()
