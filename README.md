# JhonSecurity

JhonSecurity é uma biblioteca Java avançada para implementação de recursos de segurança, incluindo análise comportamental, prevenção de ataques e criptografia.

## Índice

- [Instalação](#instalação)
- [Recursos](#recursos)
- [Como Usar](#como-usar)
- [Configuração](#configuração)
- [Exemplos](#exemplos)
- [Documentação da API](#documentação-da-api)
- [Contribuição](#contribuição)
- [Licença](#licença)

## Instalação

Para incluir a JhonSecurity em seu projeto, adicione a seguinte dependência ao seu arquivo `pom.xml`:

```xml
<dependency>
    <groupId>io.github.jhonathandosreis</groupId>
    <artifactId>jhon-security</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Recursos

- **Análise Comportamental**: Detecta padrões suspeitos de uso
- **Prevenção de Ataques**: Proteção contra ataques comuns
- **Criptografia Avançada**: Implementação segura usando AES/GCM
- **Configuração Flexível**: Diferentes níveis de segurança
- **Logging Integrado**: Monitoramento detalhado de eventos

## Como Usar

### Inicialização Básica

```java
JhonSecurity security = JhonSecurity.builder()
    .withSecurityLevel(SecurityLevel.HIGH)
    .withBehavioralAnalysis(true)
    .withAttackPrevention(true)
    .build();
```

### Análise Comportamental

```java
SecurityEvent event = SecurityEvent.builder()
    .userId("user123")
    .location("127.0.0.1")
    .actionType("LOGIN")
    .deviceFingerprint("device-123")
    .build();

double riskScore = security.getBehaviorAnalyzer().analyzeEvent(event);
```

### Prevenção de Ataques

```java
SecurityRequest request = new SecurityRequest(
    "user123",
    "127.0.0.1",
    "Mozilla/5.0",
    Map.of("User-Agent", "Mozilla/5.0"),
    "/api/data"
);

boolean shouldBlock = security.getAttackPreventor().shouldBlock(request);
```

### Criptografia

```java
String dadosSensiveis = "informação confidencial";
String dadosCriptografados = security.getEncryption().encrypt(dadosSensiveis);
String dadosDecriptografados = security.getEncryption().decrypt(dadosCriptografados);
```

## Configuração

### Níveis de Segurança

A biblioteca suporta quatro níveis de segurança:

- **LOW**: Para ambientes de desenvolvimento
- **MEDIUM**: Para aplicações com requisitos básicos de segurança
- **HIGH**: Recomendado para a maioria das aplicações em produção
- **EXTREME**: Para aplicações que exigem máxima segurança

### Configuração Avançada

```java
SecurityConfig config = SecurityConfig.builder()
    .withSecurityLevel(SecurityLevel.HIGH)
    .withBehavioralAnalysis(true)
    .withAttackPrevention(true)
    .withMaxLoginAttempts(5)
    .withLockoutDuration(Duration.ofMinutes(30))
    .withMaxRequestsPerMinute(100)
    .build();

JhonSecurity security = new JhonSecurity(config);
```

## Exemplos

### Exemplo Completo de Uso

```java
// Inicialização
JhonSecurity security = JhonSecurity.builder()
    .withSecurityLevel(SecurityLevel.HIGH)
    .withBehavioralAnalysis(true)
    .withAttackPrevention(true)
    .build();

// Análise de evento
SecurityEvent loginEvent = SecurityEvent.builder()
    .userId("user123")
    .location("127.0.0.1")
    .actionType("LOGIN")
    .deviceFingerprint("device-123")
    .build();

double riskScore = security.getBehaviorAnalyzer().analyzeEvent(loginEvent);

// Verificação de ataque
SecurityRequest request = new SecurityRequest(
    "user123",
    "127.0.0.1",
    "Mozilla/5.0",
    Map.of("User-Agent", "Mozilla/5.0"),
    "/api/data"
);

if (!security.getAttackPreventor().shouldBlock(request)) {
    // Processa a requisição
}

// Criptografia de dados
String dadosSensiveis = "dados confidenciais";
String dadosCriptografados = security.getEncryption().encrypt(dadosSensiveis);
```

## Documentação da API

### BehaviorAnalyzer

Classe responsável pela análise comportamental dos usuários.

Principais métodos:
- `analyzeEvent(SecurityEvent event)`: Analisa um evento e retorna um score de risco
- `shutdown()`: Finaliza o analisador e libera recursos

### AttackPreventor

Classe que implementa a prevenção de ataques.

Principais métodos:
- `shouldBlock(SecurityRequest request)`: Verifica se uma requisição deve ser bloqueada
- `isRateLimited(String ipAddress)`: Verifica se um IP atingiu o limite de requisições

### AdvancedEncryption

Implementa a criptografia dos dados.

Principais métodos:
- `encrypt(String data)`: Criptografa dados usando AES/GCM
- `decrypt(String encryptedData)`: Descriptografa dados

## Contribuição

Para contribuir com o projeto:

1. Faça um fork do repositório
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.