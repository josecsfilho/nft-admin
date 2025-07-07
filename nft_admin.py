import subprocess
import re
import questionary
import os
import sys

NFT_CONF_PATH = "/etc/nftables.conf"

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def run_nft_list_ruleset():
    result = subprocess.run(["sudo", "nft", "list", "ruleset"], capture_output=True, text=True)
    return result.stdout

def parse_nft_conf():
    if not os.path.isfile(NFT_CONF_PATH):
        print(f"Arquivo {NFT_CONF_PATH} não encontrado. Será criado um novo na aplicação das regras.")
        return {}

    with open(NFT_CONF_PATH, "r") as f:
        content = f.read()

    profiles = {}

    # Regex para encontrar sets separados por perfil: allowed_ips_<perfil>, allowed_tcp_ports_<perfil>
    ips_pattern = re.compile(r'set allowed_ips_(\w+) \{[^}]*elements = \{([^}]*)\}', re.MULTILINE)
    ports_pattern = re.compile(r'set allowed_tcp_ports_(\w+) \{[^}]*elements = \{([^}]*)\}', re.MULTILINE)

    # Regra na chain input que referencia sets e comentário
    rule_pattern = re.compile(r'ip saddr @allowed_ips_(\w+) tcp dport @allowed_tcp_ports_\1 accept comment "(.*?)"', re.MULTILINE)

    # Extrai os IPs
    ips_found = {m.group(1): [ip.strip() for ip in m.group(2).split(",") if ip.strip()] for m in ips_pattern.finditer(content)}

    # Extrai as portas
    ports_found = {m.group(1): [p.strip() for p in m.group(2).split(",") if p.strip()] for m in ports_pattern.finditer(content)}

    # Extrai comentários
    comments_found = {m.group(1): m.group(2) for m in rule_pattern.finditer(content)}

    # Monta perfis
    for perfil in set(list(ips_found.keys()) + list(ports_found.keys()) + list(comments_found.keys())):
        profiles[perfil] = {
            "ips": ips_found.get(perfil, []),
            "ports": ports_found.get(perfil, []),
            "comment": comments_found.get(perfil, "")
        }

    return profiles

def generate_nft_conf(profiles):
    lines = []
    lines.append("#!/usr/sbin/nft -f\n\n")
    lines.append("flush ruleset\n\n")
    lines.append("table inet filter {\n")

    # Criar sets por perfil
    for perfil, data in profiles.items():
        lines.append(f"    set allowed_ips_{perfil} {{\n")
        lines.append("        type ipv4_addr\n")
        lines.append("        flags interval\n")
        ips_line = ", ".join(data["ips"]) if data["ips"] else ""
        lines.append(f"        elements = {{ {ips_line} }}\n")
        lines.append("    }\n\n")

        lines.append(f"    set allowed_tcp_ports_{perfil} {{\n")
        lines.append("        type inet_service\n")
        ports_line = ", ".join(data["ports"]) if data["ports"] else ""
        lines.append(f"        elements = {{ {ports_line} }}\n")
        lines.append("    }\n\n")

    # Chain input
    lines.append("    chain input {\n")
    lines.append("        type filter hook input priority filter; policy drop;\n")
    lines.append('        iif "lo" accept comment "Loopback"\n')
    lines.append('        ct state established,related accept comment "Conexões estabelecidas"\n')
    lines.append('        ip protocol icmp accept comment "Ping IPv4"\n')
    lines.append('        ip6 nexthdr ipv6-icmp accept comment "Ping IPv6"\n\n')

    # Regras para cada perfil
    for perfil, data in profiles.items():
        if data["ips"] and data["ports"]:
            comment = data["comment"].replace('"', "'")
            lines.append(f'        ip saddr @allowed_ips_{perfil} tcp dport @allowed_tcp_ports_{perfil} accept comment "{comment}"\n')

    lines.append('\n        log prefix "nftables-drop: " flags all counter comment "Log pacotes bloqueados"\n')
    lines.append('        drop comment "Bloquear demais pacotes"\n')
    lines.append("    }\n")

    # Chain output e forward básicos
    lines.append("    chain output {\n")
    lines.append("        type filter hook output priority filter; policy accept;\n")
    lines.append("    }\n")

    lines.append("    chain forward {\n")
    lines.append("        type filter hook forward priority filter; policy drop;\n")
    lines.append("    }\n")

    lines.append("}\n")

    return "".join(lines)

def save_nft_conf(profiles):
    conf_text = generate_nft_conf(profiles)
    with open(NFT_CONF_PATH, "w") as f:
        f.write(conf_text)

def apply_rules():
    try:
        subprocess.run(["sudo", "nft", "-f", NFT_CONF_PATH], check=True)
        print("Regras aplicadas com sucesso.")
    except subprocess.CalledProcessError:
        print("Erro ao aplicar regras.")

def list_profiles(profiles):
    clear()
    print("Perfis de firewall e regras atuais:\n")
    print(f"{'Perfil':<15} {'IPs':<30} {'Portas':<20} Comentário")
    print("-" * 90)
    for perfil, data in profiles.items():
        ips = ", ".join(data["ips"])
        ports = ", ".join(data["ports"])
        comment = data["comment"]
        print(f"{perfil:<15} {ips:<30} {ports:<20} {comment}")
    input("\nPressione Enter para continuar...")

def input_ip():
    while True:
        ip = questionary.text("Digite o IP ou rede (ex: 192.168.0.0/16):").ask()
        if ip:
            import ipaddress
            try:
                ipaddress.ip_network(ip)
                return ip
            except ValueError:
                print("IP inválido, tente novamente.")
        else:
            print("Entrada obrigatória.")

def input_ports():
    while True:
        ports = questionary.text("Digite portas separadas por vírgula (ex: 22,80,443):").ask()
        if ports:
            ports_list = [p.strip() for p in ports.split(",") if p.strip().isdigit()]
            if ports_list:
                return ports_list
            else:
                print("Informe ao menos uma porta válida.")
        else:
            print("Entrada obrigatória.")

def input_comment():
    comment = questionary.text("Digite um comentário para o perfil:").ask()
    return comment if comment else ""

def add_profile(profiles):
    clear()
    perfil = questionary.text("Nome do perfil (ex: brazil, dmz):").ask()
    if not perfil or perfil in profiles:
        print("Perfil inválido ou já existente.")
        return

    ips = []
    while True:
        ip = input_ip()
        ips.append(ip)
        mais = questionary.confirm("Adicionar outro IP/rede?").ask()
        if not mais:
            break

    ports = input_ports()
    comment = input_comment()

    profiles[perfil] = {
        "ips": ips,
        "ports": ports,
        "comment": comment
    }
    print(f"Perfil '{perfil}' adicionado.")

def remove_profile(profiles):
    clear()
    if not profiles:
        print("Nenhum perfil cadastrado.")
        input("Pressione Enter para continuar...")
        return
    perfil = questionary.select("Selecione o perfil para remover:", choices=list(profiles.keys())).ask()
    if perfil:
        confirm = questionary.confirm(f"Confirma remoção do perfil '{perfil}'?").ask()
        if confirm:
            del profiles[perfil]
            print(f"Perfil '{perfil}' removido.")

def edit_profile(profiles):
    clear()
    if not profiles:
        print("Nenhum perfil cadastrado.")
        input("Pressione Enter para continuar...")
        return
    perfil = questionary.select("Selecione o perfil para editar:", choices=list(profiles.keys())).ask()
    if not perfil:
        return

    data = profiles[perfil]

    while True:
        clear()
        print(f"Editando perfil: {perfil}\n")
        print(f"IPs: {', '.join(data['ips'])}")
        print(f"Portas: {', '.join(data['ports'])}")
        print(f"Comentário: {data['comment']}\n")

        option = questionary.select(
            "Escolha o que deseja editar:",
            choices=[
                "Adicionar IP",
                "Remover IP",
                "Adicionar porta",
                "Remover porta",
                "Editar comentário",
                "Voltar"
            ],
        ).ask()

        if option == "Adicionar IP":
            ip = input_ip()
            if ip not in data["ips"]:
                data["ips"].append(ip)
                print("IP adicionado.")
            else:
                print("IP já existe no perfil.")
        elif option == "Remover IP":
            if not data["ips"]:
                print("Nenhum IP para remover.")
            else:
                ip = questionary.select("Selecione o IP para remover:", choices=data["ips"]).ask()
                if ip:
                    data["ips"].remove(ip)
                    print("IP removido.")
        elif option == "Adicionar porta":
            ports = input_ports()
            added = 0
            for p in ports:
                if p not in data["ports"]:
                    data["ports"].append(p)
                    added += 1
            print(f"{added} porta(s) adicionada(s).")
        elif option == "Remover porta":
            if not data["ports"]:
                print("Nenhuma porta para remover.")
            else:
                p = questionary.select("Selecione a porta para remover:", choices=data["ports"]).ask()
                if p:
                    data["ports"].remove(p)
                    print("Porta removida.")
        elif option == "Editar comentário":
            comment = input_comment()
            data["comment"] = comment
            print("Comentário atualizado.")
        elif option == "Voltar":
            break
        input("\nPressione Enter para continuar...")

def main():
    try:
        while True:
            clear()
            profiles = parse_nft_conf()

            choice = questionary.select(
                "Selecione a ação:",
                choices=[
                    "Listar perfis",
                    "Adicionar perfil",
                    "Editar perfil",
                    "Remover perfil",
                    "Aplicar regras",
                    "Sair"
                ],
            ).ask()

            if choice == "Listar perfis":
                list_profiles(profiles)
            elif choice == "Adicionar perfil":
                add_profile(profiles)
                save_nft_conf(profiles)
            elif choice == "Editar perfil":
                edit_profile(profiles)
                save_nft_conf(profiles)
            elif choice == "Remover perfil":
                remove_profile(profiles)
                save_nft_conf(profiles)
            elif choice == "Aplicar regras":
                save_nft_conf(profiles)
                apply_rules()
                input("Pressione Enter para continuar...")
            elif choice == "Sair":
                print("Encerrando...")
                sys.exit(0)
            else:
                print("Opção inválida.")
    except KeyboardInterrupt:
        print("\nPrograma encerrado pelo usuário.")

if __name__ == "__main__":
    main()
