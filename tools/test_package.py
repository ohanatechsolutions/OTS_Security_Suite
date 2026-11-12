import json
import unittest
from pathlib import Path
from xml.etree import ElementTree
ROOT = Path(__file__).resolve().parents[1]
class ReleaseManifestTests(unittest.TestCase):
    def test_windows_icon_is_source_configured(self):
        proj = (ROOT/'src/OTSSecuritySuite.Desktop/OTSSecuritySuite.Desktop.csproj').read_text(encoding="utf-8")
        xaml = (ROOT/'src/OTSSecuritySuite.Desktop/MainWindow.xaml').read_text(encoding="utf-8")
        self.assertIn('<ApplicationIcon>AppIcon.ico</ApplicationIcon>',proj)
        self.assertIn('Icon="AppIcon.ico"',xaml)
        self.assertTrue((ROOT/'src/OTSSecuritySuite.Desktop/AppIcon.ico').is_file())
        self.assertTrue((ROOT/'src/OTSSecuritySuite.Desktop/OhanaLogo.png').is_file())
    def test_xaml_parses(self):
        for f in (ROOT/'src/OTSSecuritySuite.Desktop').glob('*.xaml'):
            ElementTree.parse(f)
    def test_suite_taskbar_identity_matches_installer_shortcuts(self):
        host = (ROOT/'src/OTSSecuritySuite.Desktop/App.xaml.cs').read_text(encoding="utf-8")
        setup = (ROOT/'installer/OTS-Security-Suite.iss').read_text(encoding="utf-8")
        identifier = 'OhanaTechSolutions.OTSSecuritySuite'
        self.assertIn('SetCurrentProcessExplicitAppUserModelID', host)
        self.assertIn(identifier, host)
        self.assertEqual(setup.count('AppUserModelID: "'+identifier+'"'), 2)

    def test_extension_manifest_valid(self):
        m = json.loads((ROOT/'extension/manifest.json').read_text(encoding="utf-8"))
        self.assertEqual(m['manifest_version'],3)
        self.assertEqual(m['permissions'], ['activeTab'])
        self.assertNotIn('host_permissions', m, "Popup URL lookup requires no permanent host privileges")
        self.assertNotIn('tabs', m['permissions'], "Avoid access to unrelated browser tabs")
        self.assertNotIn('http://127.0.0.1:48728', (ROOT/'extension/popup.js').read_text(encoding="utf-8"))
    def test_submodule_locations(self):
        m = (ROOT/'.gitmodules').read_text(encoding="utf-8")
        self.assertIn('OTS_W.H.I.T.E.',m)
        self.assertIn('OTS_System_Santizer',m)
if __name__=='__main__': unittest.main()
