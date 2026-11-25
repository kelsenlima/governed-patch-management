"""
Testes do parser do Qualys e da política de patch.

Rodar:  python -m unittest discover -s tests -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "scripts"))

import qualys_lib as q  # noqa: E402
import gerar_plano as gp  # noqa: E402

FIX = os.path.join(RAIZ, "tests", "fixtures")


def ler(nome):
    with open(os.path.join(FIX, nome), encoding="utf-8") as f:
        return f.read()


class TestParserResultado(unittest.TestCase):
    def test_tabela_com_tab(self):
        p = q.parse_resultado("Package\tInstalled Version\tRequired Version\nlinux\t6.8.0-1066-gcp\t6.8.0-1073")
        self.assertEqual([(x.nome, x.instalada, x.exigida) for x in p], [("linux", "6.8.0-1066-gcp", "6.8.0-1073")])

    def test_tabela_com_espacos_e_varias_linhas(self):
        p = q.parse_resultado(
            "Package Installed Version Required Version\n"
            "openssl-libs 1:1.1.1k-12.el8_9 1:1.1.1k-14.el8_10\n"
            "sudo 1.9.5p2-1.el8_9 1.9.5p2-1.el8_10"
        )
        self.assertEqual([x.nome for x in p], ["openssl-libs", "sudo"])
        self.assertEqual(p[0].exigida, "1:1.1.1k-14.el8_10")

    def test_sem_tabela(self):
        self.assertEqual(q.parse_resultado("%windir%\\System32\\mscoree.dll Version is 4.8"), [])
        self.assertEqual(q.parse_resultado(""), [])


class TestCsv(unittest.TestCase):
    def test_ignora_fixed_e_le_campos(self):
        dets = q.parse_deteccoes_csv(ler("deteccoes.csv"))
        self.assertTrue(all(d.status in q.ABERTOS for d in dets))
        self.assertNotIn("6800003", [d.qid for d in dets])  # Fixed
        alvo = [d for d in dets if d.ip == "10.20.1.11"]
        self.assertEqual(alvo[0].nome, "web-prd-01")
        self.assertEqual(alvo[0].pacotes[0].nome, "linux")

    def test_nome_fqdn_vira_curto(self):
        dets = q.parse_deteccoes_csv(ler("deteccoes.csv"))
        win = [d for d in dets if d.windows][0]
        self.assertEqual(win.nome, "win-web-prd-01")

    def test_kb(self):
        kb = q.parse_kb(ler("kb.xml"))
        self.assertEqual(kb["5001508"]["categoria"], "SCA")
        self.assertIn("Linux kernel", kb["6877835"]["titulo"])


class TestWindows(unittest.TestCase):
    def test_classificacao(self):
        c = q.classificar_windows
        self.assertEqual(c("Microsoft Windows Security Update for November 2026", "Windows", "KB5046617 is not installed")["classe"], "WINDOWS_UPDATE")
        self.assertEqual(c("Microsoft .NET Framework Security Update", "Windows", "")["classe"], "WINDOWS_UPDATE")
        self.assertEqual(c("Microsoft .NET Core and ASP.NET Core Security Update", "Windows", "")["classe"], "MICROSOFT_APP")
        self.assertEqual(c("Microsoft Office Security Update", "Office Application", "")["classe"], "MICROSOFT_APP")
        self.assertEqual(c("Microsoft Edge Based on Chromium Prior to 131", "Local", "")["classe"], "MICROSOFT_APP")
        self.assertEqual(c("Google Chrome Prior to 131.0 Multiple Vulnerabilities", "Local", "")["classe"], "TERCEIROS")
        self.assertEqual(c("Oracle Java SE Critical Patch Update", "Local", "")["classe"], "TERCEIROS")
        self.assertEqual(c("SSL Certificate - Self-Signed Certificate", "General remote services", "")["classe"], "CONFIG")
        self.assertEqual(c("SMB Signing Disabled or SMB Signing Not Required", "Windows", "")["classe"], "CONFIG")
        self.assertEqual(c("x", "Windows", "KB5046617 is not installed")["kbs"], ["KB5046617"])
        self.assertEqual(c("Microsoft Windows SMB Signing Not Required", "Windows", "")["classe"], "CONFIG")
        self.assertEqual(c("Microsoft Windows TLS 1.0 Enabled", "Windows", "")["classe"], "CONFIG")
        self.assertEqual(c("Microsoft Windows Remote Desktop Services RCE", "Windows", "KB5046617")["classe"], "WINDOWS_UPDATE")

    def test_mapa_windows(self):
        m = q.mapa_windows(q.carregar_yaml(os.path.join(RAIZ, "inventories", "windows.yml")))
        self.assertEqual(m["win-app-prd-01"], {"host": "win-app-prd-01", "ambiente": "producao"})
        self.assertEqual(m["win-rpa-prd-01"]["host"], "WIN-RPA-PRD-01")
        self.assertEqual(m["win-web-hml-01"]["ambiente"], "nao_producao")


class TestPolitica(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pol = q.carregar_yaml(os.path.join(RAIZ, "policy", "policy.yml"))
        cls.inv = q.mapa_inventario(q.carregar_yaml(os.path.join(RAIZ, "inventories", "hosts.yml")))

    def test_inventario_ambientes(self):
        self.assertEqual(self.inv["10.20.1.11"], {"host": "web-prd-01", "ambiente": "producao"})
        self.assertEqual(self.inv["10.20.2.22"]["host"], "app-hml-01")
        self.assertEqual(self.inv["10.20.2.22"]["ambiente"], "nao_producao")
        self.assertNotIn("10.20.0.25", self.inv)  # agente fora da esteira

    def test_rotas(self):
        r = gp.rota_do_pacote
        self.assertEqual(r("linux", "producao", self.pol)[0], "JANELA")
        self.assertEqual(r("linux", "nao_producao", self.pol)[0], "KERNEL")
        self.assertEqual(r("nginx", "producao", self.pol)[0], "JANELA")
        self.assertEqual(r("nginx", "nao_producao", self.pol)[0], "AUTO")
        self.assertEqual(r("libxml2", "producao", self.pol)[0], "AUTO")
        self.assertEqual(r("telnet", "nao_producao", self.pol)[0], "REMOVER")

    def test_plano_completo(self):
        with tempfile.TemporaryDirectory() as tmp:
            det = os.path.join(tmp, "deteccoes.json")
            env = dict(os.environ)
            subprocess.run(
                [sys.executable, os.path.join(RAIZ, "scripts", "qualys_coleta.py"),
                 "--policy", os.path.join(RAIZ, "policy", "policy.yml"), "--saida", det,
                 "--csv-local", os.path.join(FIX, "deteccoes.csv"), "--kb-local", os.path.join(FIX, "kb.xml")],
                check=True, capture_output=True, env=env,
            )
            subprocess.run(
                [sys.executable, os.path.join(RAIZ, "scripts", "gerar_plano.py"), "--entrada", det,
                 "--policy", os.path.join(RAIZ, "policy", "policy.yml"),
                 "--inventario", os.path.join(RAIZ, "inventories", "hosts.yml"), "--saida", tmp],
                check=True, capture_output=True,
            )
            with open(os.path.join(tmp, "plano.json"), encoding="utf-8") as f:
                plano = json.load(f)

        h = plano["hosts"]
        # SCA (laravel) ficou fora; Fixed (curl) ficou fora
        self.assertNotIn("5001508", h["web-prd-01"]["qids"])
        # Produção: kernel fica na lista KERNEL mas exige janela; nginx vai para JANELA
        self.assertEqual(h["web-prd-01"]["pacotes"]["KERNEL"], ["linux"])
        self.assertTrue(h["web-prd-01"]["kernel_exige_janela"])
        self.assertEqual(h["web-prd-01"]["pacotes"]["JANELA"], ["nginx"])
        self.assertEqual(h["web-prd-01"]["pacotes"]["AUTO"], ["libxml2", "libxml2-utils"])
        self.assertTrue(h["web-prd-01"]["reboot_necessario"])
        # Não-produção: kernel com reboot liberado, nginx automático, telnet para remover
        self.assertFalse(h["web-hml-01"]["kernel_exige_janela"])
        self.assertEqual(h["web-hml-01"]["pacotes"]["AUTO"], ["nginx"])
        self.assertEqual(h["web-hml-01"]["pacotes"]["REMOVER"], ["telnet"])
        # Rocky: openssl-libs é protegido → JANELA; sudo → AUTO
        self.assertEqual(h["proxy-prd-01"]["pacotes"]["JANELA"], ["openssl-libs"])
        self.assertEqual(h["proxy-prd-01"]["pacotes"]["AUTO"], ["sudo"])
        # Fora do inventário: servidor que nenhum inventário conhece aparece listado
        self.assertTrue(any("maquina-nova" in k for k in plano["fora_inventario"]))
        # Windows (W1): servidor do inventário Windows vai para a seção "windows", classificado
        w = plano["windows"]["win-app-prd-01"]
        self.assertEqual(w["ambiente"], "producao")
        self.assertEqual(w["criticas"], 1)
        self.assertEqual(w["altas"], 3)
        self.assertEqual(w["por_classe"]["WINDOWS_UPDATE"], 1)
        self.assertEqual(w["por_classe"]["TERCEIROS"], 1)
        self.assertEqual(w["por_classe"]["CONFIG"], 1)
        self.assertEqual(w["por_classe"]["MICROSOFT_APP"], 1)
        self.assertIn("KB5046617", w["kbs"])
        self.assertNotIn("win-app-prd-01", h)                      # nunca entra no patch Linux
        # win-web-prd-01 está no inventário Windows: vai para a seção "windows"
        self.assertIn("win-web-prd-01", plano["windows"])
        self.assertFalse(any("win-web-prd-01" in k for k in plano["fora_inventario"]))
        # Contagem por vulnerabilidade: kernel em produção precisa de janela
        self.assertEqual(h["web-prd-01"]["det_por_rota"], {"JANELA_KERNEL": 1, "AUTO": 1, "JANELA": 1})
        self.assertEqual(h["web-hml-01"]["det_por_rota"], {"KERNEL": 1, "AUTO": 1, "REMOVER": 1})


if __name__ == "__main__":
    unittest.main()
