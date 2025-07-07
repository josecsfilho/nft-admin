# nft-admin

**nft-admin** é uma ferramenta de gerenciamento de regras de firewall `nftables` para sistemas Linux, desenvolvida em Python com uma interface CLI interativa.  
Seu objetivo é ser simples, segura e fácil de usar, permitindo a administração de regras sem a necessidade de edição manual de arquivos.

## Funcionalidades

- Interface interativa com `questionary`
- Gerenciamento de perfis de IPs e portas
- Comentários descritivos por regra diretamente no `/etc/nftables.conf`
- Aplicação das regras via `nft -f`
- Edição completa de perfis (IPs, portas, comentários)
- Sem uso de arquivos JSON ou banco externo — apenas o `.conf` oficial

## 📂 Estrutura

```bash
nft-admin/
├── nft_admin.py           # Lógica de gerenciamento de regras
├── requirements.txt       # Dependências do projeto
└── .gitignore             # Ignora o venv e cache
# nft-admin
