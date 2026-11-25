"""
Valida inventories/host_vars/*.yml (health check da aplicação por servidor).

Roda na pipeline junto com os demais testes: um host_vars quebrado ou com
servidor que não existe no inventário PARA a esteira antes de tocar em qualquer host.
"""

import glob
import os
import unittest

import yaml

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST_VARS = os.path.join(RAIZ, "inventories", "host_vars")

CHAVES_PERMITIDAS = {"servicos_criticos", "health_urls", "health_iis", "health_status_ok"}

# Servidores Linux do inventário ainda SEM host_vars, com o motivo (manter curto e atualizado)
LINUX_PENDENTES = {
    "web-hml-02": "exemplo: chave SSH do Ansible ainda não autorizada (Permission denied)",
}


def _hosts(inventario: str) -> set[str]:
    with open(os.path.join(RAIZ, "inventories", inventario), encoding="utf-8") as f:
        dados = yaml.safe_load(f)
    achados: set[str] = set()

    def andar(no):
        if not isinstance(no, dict):
            return
        for nome, h in (no.get("hosts") or {}).items():
            achados.add(nome)
        for filho in (no.get("children") or {}).values():
            andar(filho)

    andar(dados.get("all", {}))
    return achados


class TestHostVars(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.linux = _hosts("hosts.yml")
        cls.windows = _hosts("windows.yml")
        cls.arquivos = {
            os.path.splitext(os.path.basename(a))[0]: a
            for a in glob.glob(os.path.join(HOST_VARS, "*.yml"))
        }

    def test_yaml_valido_e_chaves_conhecidas(self):
        for host, arq in self.arquivos.items():
            with self.subTest(host=host):
                with open(arq, encoding="utf-8") as f:
                    d = yaml.safe_load(f)
                self.assertIsInstance(d, dict, f"{arq}: precisa ser um mapa YAML")
                desconhecidas = set(d) - CHAVES_PERMITIDAS - {k for k in d if k.startswith("patch_")}
                self.assertFalse(desconhecidas, f"{arq}: chaves desconhecidas {desconhecidas}")
                self.assertIsInstance(d.get("servicos_criticos", []), list)
                self.assertTrue(all(isinstance(s, str) and s.strip() for s in d.get("servicos_criticos", [])))
                for u in d.get("health_urls", []):
                    self.assertRegex(u, r"^https?://[^\s/]+(:\d+)?/", f"{arq}: URL inválida {u}")

    def test_servidor_existe_no_inventario(self):
        for host in self.arquivos:
            with self.subTest(host=host):
                self.assertIn(host, self.linux | self.windows,
                              f"host_vars/{host}.yml não corresponde a nenhum servidor do inventário")

    def test_todo_linux_tem_host_vars_ou_pendencia_registrada(self):
        sem = sorted(self.linux - set(self.arquivos) - set(LINUX_PENDENTES))
        self.assertFalse(sem, f"Servidores Linux sem host_vars e sem pendência registrada: {sem} "
                              "(rodar o modo 🔍 Descobrir serviços)")

    def test_pendencia_resolvida_deve_sair_da_lista(self):
        resolvidos = sorted(set(LINUX_PENDENTES) & set(self.arquivos))
        self.assertFalse(resolvidos, f"Já têm host_vars; tirar de LINUX_PENDENTES: {resolvidos}")


if __name__ == "__main__":
    unittest.main()
