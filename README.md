# MacOS-Tor

**MacOnion** é uma ferramenta educacional e experimental de roteamento em camadas (Onion Routing) desenvolvida em **Swift** para **macOS**, utilizando a **Network.framework** e o **CryptoKit** da Apple.

O objetivo do projeto é demonstrar, na prática, a construção de redes de privacidade, encapsulamento de pacotes em tamanho fixo, trocas de chaves efêmeras Diffie-Hellman e servidores proxy locais sem dependência de dependências C externas.

---

## Arquitetura do Sistema

- **Cliente macOS (MacOnionApp):**
  - **Socks5Server:** Proxy local escutando em `127.0.0.1:9050` que suporta a especificação SOCKS5h (resolução DNS remota).
  - **CircuitBuilder:** Seleciona aleatoriamente um circuito de 3 saltos (*Guard*, *Middle*, *Exit*) a partir da lista de nós.
  - **OnionCrypter:** Aplica 3 camadas de criptografia simétrica **ChaCha20-Poly1305** sobre células fixas de 512 bytes.
  - **KeyExchange:** Troca de chaves efêmeras **X25519** com derivação **HKDF-SHA256** para cada salto.

- **Directory Server (Servidor de Diretório):**
  - Servidor HTTP JSON que publica a lista de nós ativos com seus endereços IP, portas e chaves públicas estáticas.

- **Relays (Nós de Sobreposição):**
  - Nós que recebem células, removem a camada externa de criptografia e repassam os dados sem conhecer a origem e o destino final simultaneamente.
