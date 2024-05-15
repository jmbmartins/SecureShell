# SecureShell
Team Work SSI 

3.1 Breve Introdução

Este projeto tem como objetivo a construção de um sistema na arquitetura cliente / servidor que imite o Secure Shell. O sistema terá, portanto, uma aplicação servidor e uma aplicação cliente. Após ser colocada a correr, a aplicação servidor aceita ligações de aplicações cliente, faz a autenticação de utilizadores registados no sistema, estabelece chaves de sessão, e permite que o cliente submeta comandos na máquina anfitriã. 
Pensem numa forma de atacar o sistema (uma falha da sua implementação) e dediquemlhe um pequeno intervalo de tempo na apresentação.

3.2 Funcionalidades Básicas

Em termos de funcionalidades básicas:

- A autenticação dos clientes no sistema é feita de uma forma segura; (João Martins)

- As comunicações entre os clientes e o servidor são protegidas usando algoritmos de criptografia simétrica de qualidade; (João Marques)

- As chaves de cifra (de sessão) são geradas sempre que se inicia nova sessão e são estabelecidas chaves diferentes para todos os tipos de mecanismos criptográficos; (Rui)

- As mensagens entre clientes e servidor são protegidas com mecanismos de autenticação da origem da informação. (Fábio)

3.3 Funcionalidades Avançadas

Em termos de funcionalidades avançadas:

- O sistema é multi-plataforma (i.e., o mesmo conjunto de aplicações funciona em diferentes sistemas operativos sem muitas modificações/configurações); (João Martins)

- A autenticação é feita usando mecanismos de autenticação forte; (João Martins)

- O sistema suporta autenticação mútua (cliente e servidor); (João Martins)

- O sistema suporta vários mecanismos de troca de chaves, nomeadamente mecanismos da criptografia simétrica (e.g., chaves pré-distribuídas ou derivadas de uma palavra-passe) e assimétrica (e.g., Diffie-Hellman ou RSA);

- Em vez de um mecanismo de autenticação da origem da informação, é implementado um mecanismo de assinatura digital;

- Em vez de RSA, são usadas primitivas da criptografia sobre curvas elípticas;

- Outras funcionalidades relevantes no contexto da segurança do sistema e que o favoreçam na nota.
